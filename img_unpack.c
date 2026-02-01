#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include "rkrom_29xx.h"
#include "md5.h"

static int64_t get_file_size(FILE *fp)
{
	off_t cur = ftello(fp);
	if (cur < 0)
		return -1;
	if (fseeko(fp, 0, SEEK_END) != 0)
		return -1;
	off_t end = ftello(fp);
	if (end < 0)
		return -1;
	if (fseeko(fp, cur, SEEK_SET) != 0)
		return -1;
	return (int64_t)end;
}

int export_data(const char *filename, uint64_t offset, uint64_t length, FILE *fp)
{
	FILE *out_fp = NULL;
	unsigned char buffer[1024];

	out_fp = fopen(filename, "wb");
	if (!out_fp)
	{
		fprintf(stderr, "can't open output file \"%s\": %s\n",
			filename, strerror(errno));
		goto export_end;
	}

	if (fseeko(fp, (off_t)offset, SEEK_SET) != 0)
	{
		fprintf(stderr, "seek failed (offset=%" PRIu64 "): %s\n", offset, strerror(errno));
		goto export_end;
	}

	for (; length > 0; )
	{
		size_t want = (length < (uint64_t)sizeof(buffer)) ? (size_t)length : sizeof(buffer);
		size_t got = fread(buffer, 1, want, fp);
		if (got == 0)
		{
			fprintf(stderr, "unexpected EOF while exporting (remaining=%" PRIu64 ")\n", length);
			goto export_end;
		}
		if (fwrite(buffer, 1, got, out_fp) != got)
		{
			fprintf(stderr, "write failed: %s\n", strerror(errno));
			goto export_end;
		}
		length -= (uint64_t)got;
	}
	
	fclose(out_fp);
	return 0;
export_end:
	if (out_fp)
		fclose(out_fp);

	return -1;
}

int check_md5sum(FILE *fp, uint64_t length)
{
	unsigned char buf[1024];
	unsigned char md5sum[16];
	MD5_CTX md5_ctx;
	int i;

	if (fseeko(fp, 0, SEEK_SET) != 0)
		return -1;

	MD5_Init(&md5_ctx);
	while (length > 0)
	{
		size_t want = (length < (uint64_t)sizeof(buf)) ? (size_t)length : sizeof(buf);
		size_t got = fread(buf, 1, want, fp);
		if (got == 0)
			return -1;
		length -= (uint64_t)got;
		MD5_Update(&md5_ctx, buf, got);
	}

	MD5_Final(md5sum, &md5_ctx);

	if (32 != fread(buf, 1, 32, fp))
		return -1;

	for (i = 0; i < 16; ++i)
	{
		sprintf(buf + 32 + i * 2, "%02x", md5sum[i]);
	}

	if (strncasecmp(buf, buf + 32, 32) == 0)
		return 0;	

	return -1;
}

int unpack_rom(const char* filepath, const char* dstfile)
{
	struct _rkfw_header rom_header;

	FILE *fp = fopen(filepath, "rb");
	if (!fp)
	{
		fprintf(stderr, "Can't open file %s\n, reason: %s\n", filepath, strerror(errno));
		goto unpack_fail;
	}


	fseeko(fp, 0, SEEK_SET);
	if (1 != fread(&rom_header, sizeof(rom_header), 1, fp))
		goto unpack_fail;

	if (strncmp(RK_ROM_HEADER_CODE, rom_header.head_code, sizeof(rom_header.head_code)) != 0)
	{
		fprintf(stderr, "Invalid rom file: %s\n", filepath);
		goto unpack_fail;
	}

	printf("rom version: %x.%x.%x\n",
		(rom_header.version >> 24) & 0xFF,
		(rom_header.version >> 16) & 0xFF,
		(rom_header.version) & 0xFFFF);

	printf("build time: %d-%02d-%02d %02d:%02d:%02d\n", 
		rom_header.year, rom_header.month, rom_header.day,
		rom_header.hour, rom_header.minute, rom_header.second);

	printf("chip: %x\n", rom_header.chip);
 
	int64_t fsz = get_file_size(fp);
	if (fsz < 0)
	{
		fprintf(stderr, "Failed to get file size\n");
		goto unpack_fail;
	}

	uint64_t image_offset = (uint64_t)rom_header.image_offset;
	uint64_t hdr_end = image_offset + (uint64_t)rom_header.image_length;
	uint64_t eof_end = (fsz > 32) ? ((uint64_t)fsz - 32) : 0;

	printf("image_offset: 0x%08x\n", rom_header.image_offset);
	printf("header image_length (32-bit): 0x%08x\n", rom_header.image_length);
	printf("file_size: %" PRIu64 "\n", (uint64_t)fsz);

	printf("checking md5sum....");
	fflush(stdout);
	uint64_t md5_end = hdr_end;

	if (check_md5sum(fp, hdr_end) != 0)
	{
		// Common RKFW variant: ASCII MD5 is last 32 bytes of file
		if (eof_end && check_md5sum(fp, eof_end) == 0)
		{
			md5_end = eof_end;
		}
		else
		{
			printf("Not match!\n");
			goto unpack_fail;
		}
	}
	printf("OK\n");
 
	if (md5_end <= image_offset)
	{
		fprintf(stderr, "Invalid computed image span (md5_end=%" PRIu64 ", image_offset=%" PRIu64 ")\n",
			md5_end, image_offset);
		goto unpack_fail;
	}

	uint64_t real_image_len = md5_end - image_offset;
	printf("exporting image: offset=%" PRIu64 " len=%" PRIu64 "\n", image_offset, real_image_len);

	//export_data(loader_filename, rom_header.loader_offset, rom_header.loader_length, fp);
	if (export_data(dstfile, image_offset, real_image_len, fp) != 0)
		goto unpack_fail;

	fclose(fp);
	return 0;
unpack_fail:
	if (fp)
		fclose(fp);
	return -1;
}

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		fprintf(stderr, "usage: %s <source> <destination>\n", argv[0]);
		return 1;
	}
	
	unpack_rom(argv[1], argv[2]);

	return 0;
}
