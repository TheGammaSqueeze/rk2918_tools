#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>

#include "rkcrc.h"

#define MAGIC_CODE "KRNL"

struct krnl_header
{
	char magic[4];
	unsigned int length;
};

int pack_krnl(FILE *fp_in, FILE *fp_out)
{
	unsigned char buf[1024];
	struct krnl_header header =
	{
		"KRNL",
		0
	};

	uint32_t crc = 0;
	uint64_t length64 = 0;

	fwrite(&header, sizeof(header), 1, fp_out);

	while (1)
	{
		size_t readlen = fread(buf, 1, sizeof(buf), fp_in);
		if (readlen == 0)
			break;

		length64 += (uint64_t)readlen;
		fwrite(buf, 1, readlen, fp_out);
		RKCRC(crc, buf, readlen);
	}

	fwrite(&crc, sizeof(crc), 1, fp_out);

	if (length64 > (uint64_t)UINT32_MAX)
		fprintf(stderr, "WARNING: kernel length truncated (len=%" PRIu64 ")\n", length64);

	header.length = (unsigned int)length64;

	fseeko(fp_out, 0, SEEK_SET);
	fwrite(&header, sizeof(header), 1, fp_out);

	printf("%08" PRIX32 "\n", crc);

	return 0;
}

int unpack_krnl(FILE *fp_in, FILE *fp_out)
{
	unsigned char buf[1024];
	struct krnl_header header;
	uint64_t length = 0;
	uint32_t crc = 0;
	uint32_t file_crc = 0;

	fprintf(stderr, "unpacking...");
	fflush(stderr);

	if (sizeof(header) != fread(&header, 1, sizeof(header), fp_in))
		goto fail;

	// CRC is stored after the payload
	if (fseeko(fp_in, (off_t)header.length + (off_t)sizeof(header), SEEK_SET) != 0)
		goto fail;

	if (sizeof(file_crc) != fread(&file_crc, 1, sizeof(file_crc), fp_in))
		goto fail;

	length = (uint64_t)header.length;

	if (fseeko(fp_in, (off_t)sizeof(header), SEEK_SET) != 0)
		goto fail;

	while (length > 0)
	{
		size_t want = length < (uint64_t)sizeof(buf) ? (size_t)length : sizeof(buf);
		size_t readlen = fread(buf, 1, want, fp_in);
		if (readlen == 0)
			break;

		length -= (uint64_t)readlen;
		fwrite(buf, 1, readlen, fp_out);
		RKCRC(crc, buf, readlen);
	}

	if (file_crc != crc)
		fprintf(stderr, "WARNING: bad crc checksum\n");

	fprintf(stderr, "OK\n");
	return 0;

fail:
	fprintf(stderr, "FAIL\n");
	return -1;
}

int main(int argc, char **argv)
{
	FILE *fp_in, *fp_out;
	int action = 0;

	if (argc != 4)
	{
		fprintf(stderr, "usage: %s [-a|-r] <input> <output>\n", argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "-a") == 0)
	{
		action = 1;
	} else if (strcmp(argv[1], "-r") == 0)
	{
		action = 2;
	} else {
		fprintf(stderr, "usage: %s [-a|-r] <input> <output>\n", argv[0]);
		return 1;
	}

	fp_in = fopen(argv[2], "rb");
	if (!fp_in)
	{
		fprintf(stderr, "can't open input file '%s': %s\n", argv[2], strerror(errno));
		return 1;
	}

	fp_out = fopen(argv[3], "wb");
	if (!fp_out)
	{
		fprintf(stderr, "can't open output file '%s': %s\n", argv[3], strerror(errno));
		fclose(fp_in);
		return 1;
	}

	switch (action)
	{
	case 1:
		pack_krnl(fp_in, fp_out);
		break;
	case 2:
		unpack_krnl(fp_in, fp_out);
		break;
	default:
		break;
	}

	fclose(fp_in);
	fclose(fp_out);

	return 0;
}
