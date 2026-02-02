#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdint.h>
#include <inttypes.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "rkcrc.h"
#include "rkafp.h"

#define UPDATE_MAGIC	"RKAF"
// Android sparse image support (needed to correctly extract sparse images when
// header.size/padded_size are vendor-truncated due to 32-bit overflow).
#define SPARSE_MAGIC 0xED26FF3A
#define SPARSE_CHUNK_TYPE_RAW       0xCAC1
#define SPARSE_CHUNK_TYPE_FILL      0xCAC2
#define SPARSE_CHUNK_TYPE_DONT_CARE 0xCAC3
#define SPARSE_CHUNK_TYPE_CRC32     0xCAC4

struct sparse_header {
	uint32_t magic;
	uint16_t major_version;
	uint16_t minor_version;
	uint16_t file_hdr_sz;
	uint16_t chunk_hdr_sz;
	uint32_t blk_sz;
	uint32_t total_blks;
	uint32_t total_chunks;
	uint32_t image_checksum;
} __attribute__((packed));

struct sparse_chunk_header {
	uint16_t chunk_type;
	uint16_t reserved1;
	uint32_t chunk_sz;   // in output blocks
	uint32_t total_sz;   // in bytes, including chunk header
} __attribute__((packed));


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

static uint32_t filestream_crc(FILE *fs, uint64_t stream_len)
{
	unsigned char buffer[1024];
	uint32_t crc = 0;

	while (stream_len > 0)
	{
		size_t want = stream_len < (uint64_t)sizeof(buffer) ? (size_t)stream_len : sizeof(buffer);
		size_t got = fread(buffer, 1, want, fs);
		if (got == 0)
			break;

		RKCRC(crc, buffer, got);
		stream_len -= (uint64_t)got;
	}

	return crc;
}

static uint64_t align_up_u64(uint64_t v, uint64_t a)
{
	return (a == 0) ? v : ((v + a - 1) / a) * a;
}

// Compute the actual input byte length of an Android sparse image, starting at
// file offset 'pos'. This is required because some vendor RKAF packages store
// a truncated 32-bit 'size' field for large sparse images (notably super.img).
static int compute_sparse_input_len(FILE *fp, uint64_t pos, uint64_t max_avail, uint64_t *out_len)
{
	struct sparse_header sh;
	uint64_t total = 0;
	uint32_t i;

	if (max_avail < sizeof(sh))
		return -1;

	if (fseeko(fp, (off_t)pos, SEEK_SET) != 0)
		return -1;
	if (fread(&sh, 1, sizeof(sh), fp) != sizeof(sh))
		return -1;
	if (sh.magic != SPARSE_MAGIC)
		return -1;
	if (sh.file_hdr_sz < sizeof(sh))
		return -1;
	if (sh.chunk_hdr_sz < sizeof(struct sparse_chunk_header))
		return -1;

	// Skip to end of sparse file header (can be larger than struct sparse_header)
	total = sh.file_hdr_sz;
	if (total > max_avail)
		return -1;
	if (fseeko(fp, (off_t)(pos + sh.file_hdr_sz), SEEK_SET) != 0)
		return -1;

	for (i = 0; i < sh.total_chunks; i++) {
		struct sparse_chunk_header ch;
		uint64_t data = 0;
		uint64_t declared = 0;
		uint64_t need = 0;

		if (total + sh.chunk_hdr_sz > max_avail)
			return -1;

		// Read standard chunk header first
		if (fread(&ch, 1, sizeof(ch), fp) != sizeof(ch))
			return -1;
		// Skip extended chunk header bytes if any
		if (sh.chunk_hdr_sz > sizeof(ch)) {
			uint64_t extra = (uint64_t)sh.chunk_hdr_sz - (uint64_t)sizeof(ch);
			if (total + sizeof(ch) + extra > max_avail)
				return -1;
			if (fseeko(fp, (off_t)extra, SEEK_CUR) != 0)
				return -1;
		}

		total += sh.chunk_hdr_sz;

		switch (ch.chunk_type) {
		case SPARSE_CHUNK_TYPE_RAW:
			data = (uint64_t)ch.chunk_sz * (uint64_t)sh.blk_sz;
			break;
		case SPARSE_CHUNK_TYPE_FILL:
			data = 4;
			break;
		case SPARSE_CHUNK_TYPE_DONT_CARE:
			data = 0;
			break;
		case SPARSE_CHUNK_TYPE_CRC32:
			data = 4;
			break;
		default:
			return -1;
		}

		need = data;
		if (ch.total_sz >= sh.chunk_hdr_sz) {
			declared = (uint64_t)ch.total_sz - (uint64_t)sh.chunk_hdr_sz;
			if (declared <= data)
				need = declared;
		}

		if (total + need > max_avail)
			return -1;
		if (need) {
			if (fseeko(fp, (off_t)need, SEEK_CUR) != 0)
				return -1;
			total += need;
		}
	}

	*out_len = total;
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// unpack functions

int create_dir(char *dir) {
	char *sep = dir;
	while ((sep = strchr(sep, '/')) != NULL) {
		*sep = '\0';
		if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
			printf("Can't create directory: %s\n", dir);
			return -1;
		}

		*sep = '/';
		sep++;
	}

	return 0;
}

static int extract_file(FILE *fp, uint64_t ofst, uint64_t len, const char *path)
{
	FILE *ofp;
	unsigned char buffer[1024];

	if ((ofp = fopen(path, "wb")) == NULL) {
		printf("Can\'t open/create file: %s\n", path);
		return -1;
	}

	if (fseeko(fp, (off_t)ofst, SEEK_SET) != 0) {
		printf("Can\'t seek input file to offset=%" PRIu64 " (%s)\n", ofst, strerror(errno));
		fclose(ofp);
		return -1;
	}

	while (len > 0)
	{
		size_t want = len < (uint64_t)sizeof(buffer) ? (size_t)len : sizeof(buffer);
		size_t got = fread(buffer, 1, want, fp);
		if (got == 0) {
			printf("Unexpected EOF while extracting %s\n", path);
			fclose(ofp);
			return -1;
		}
		if (fwrite(buffer, 1, got, ofp) != got) {
			printf("Write failed for %s: %s\n", path, strerror(errno));
			fclose(ofp);
			return -1;
		}
		len -= (uint64_t)got;
	}
	fclose(ofp);

	return 0;
}

int unpack_update(const char* srcfile, const char* dstdir)
{
	FILE *fp = NULL;
	struct update_header header;
	uint64_t data_end = 0;
	uint32_t file_crc_le = 0;
	uint32_t file_crc_be = 0;
	uint32_t calc_crc = 0;
	uint64_t payload_len = 0;
	uint64_t crc_offset = 0;
	int crc_ok = 0;
	int64_t fsz = 0;

	fp = fopen(srcfile, "rb");
	if (!fp) {
		fprintf(stderr, "can't open file \"%s\": %s\n", srcfile, strerror(errno));
		goto unpack_fail;
	}

	if (fseeko(fp, 0, SEEK_SET) != 0) {
		fprintf(stderr, "Can't seek image header\n");
		goto unpack_fail;
	}
	if (sizeof(header) != fread(&header, 1, sizeof(header), fp)) {
		fprintf(stderr, "Can't read image header\n");
		goto unpack_fail;
	}

	if (strncmp(header.magic, RKAFP_MAGIC, sizeof(header.magic)) != 0) {
		fprintf(stderr, "Invalid header magic\n");
		goto unpack_fail;
	}

	fsz = get_file_size(fp);
	if (fsz < 0) {
		fprintf(stderr, "Can't determine file size\n");
		goto unpack_fail;
	}
	if ((uint64_t)fsz < (uint64_t)sizeof(header) + 4) {
		fprintf(stderr, "File too small to be a valid update image\n");
		goto unpack_fail;
	}

	printf("Check file...");
	fflush(stdout);

	// Candidate payload lengths (payload is [0, payload_len), CRC is the 4 bytes at offset payload_len)
	//  1) optional extended length: header.reserved = "RK64" + uint64_t(payload_len)
	//  2) legacy: header.length (uint32)
	//  3) common in the wild: CRC is last 4 bytes of file (payload_len = file_size - 4)
	{
		uint64_t cand[3];
		int cand_n = 0;
		int i;

		if (memcmp(header.reserved, "RK64", 4) == 0) {
			uint64_t ext_len = 0;
			memcpy(&ext_len, header.reserved + 4, sizeof(ext_len));
			if (ext_len > 0 && ext_len + 4 <= (uint64_t)fsz) {
				cand[cand_n++] = ext_len;
			}
		}

		if (header.length != 0 && (uint64_t)header.length + 4 <= (uint64_t)fsz) {
			cand[cand_n++] = (uint64_t)header.length;
		}

		cand[cand_n++] = (uint64_t)fsz - 4;

		for (i = 0; i < cand_n; i++) {
			uint8_t crc_bytes[4];
			uint64_t pl = cand[i];

			if (pl + 4 > (uint64_t)fsz)
				continue;

			if (fseeko(fp, (off_t)pl, SEEK_SET) != 0)
				continue;
			if (fread(crc_bytes, 1, sizeof(crc_bytes), fp) != sizeof(crc_bytes))
				continue;

			file_crc_le = (uint32_t)crc_bytes[0] |
				((uint32_t)crc_bytes[1] << 8) |
				((uint32_t)crc_bytes[2] << 16) |
				((uint32_t)crc_bytes[3] << 24);

			file_crc_be = ((uint32_t)crc_bytes[0] << 24) |
				((uint32_t)crc_bytes[1] << 16) |
				((uint32_t)crc_bytes[2] << 8) |
				((uint32_t)crc_bytes[3] << 0);

			if (fseeko(fp, 0, SEEK_SET) != 0)
				continue;

			calc_crc = filestream_crc(fp, pl);

			if (calc_crc == file_crc_le || calc_crc == file_crc_be) {
				crc_ok = 1;
				payload_len = pl;
				crc_offset = pl;
				break;
			}
		}
	}

	if (!crc_ok) {
		printf("Fail (continuing without CRC verification)\n");
		data_end = (uint64_t)fsz;
	} else {
		printf("OK\n");
		data_end = payload_len;
	}

	printf("------- UNPACK -------\n");
	if (crc_ok && payload_len != (uint64_t)header.length) {
		printf("NOTE: header.length=0x%08X, using payload_len=%" PRIu64 "\n", header.length, payload_len);
	}

	if (header.num_parts) {
		unsigned i;
		char out_path[PATH_MAX];
		uint64_t seq_pos = sizeof(header);
		uint64_t prev_pos = 0;
		unsigned num = header.num_parts;
		int header_truncated = ((uint64_t)header.length + 4 < (uint64_t)fsz);
		uint64_t max_end = seq_pos;

		if (num > 16) {
			fprintf(stderr, "WARNING: header.num_parts=%u (clamping to 16)\n", num);
			num = 16;
		}

		// Ensure conventional output layout exists (package-file at root, payload under Image/)
		snprintf(out_path, sizeof(out_path), "%s/Image/._", dstdir);
		create_dir(out_path);

		for (i = 0; i < num; i++) {
			struct update_part *part = &header.parts[i];
			uint64_t part_pos = (uint64_t)part->pos;
			uint64_t part_size_raw = (uint64_t)part->size;
			uint64_t part_size = part_size_raw;
			uint64_t part_padded = (uint64_t)part->padded_size;
			uint64_t seq_part_pos = seq_pos;
			int use_seq = 0;
			int is_parameter = 0;
			int is_sparse = 0;
			uint64_t padded_effective = 0;

			if (strcmp(part->filename, "SELF") == 0) {
				printf("%s	<SELF>\n", part->filename);
				continue;
			}

			// Default padding used by this toolchain is 2048 bytes
			if (part_padded == 0 || part_padded < part_size_raw) {
				uint64_t pad = 2048;
				part_padded = (part_size_raw + (pad - 1)) / pad * pad;
			}
			seq_pos += part_padded;

			// Prefer sequential offsets when header fields wrap or look inconsistent
			if (header_truncated)
				use_seq = 1;
			if (part_pos < sizeof(header))
				use_seq = 1;
			if (part_pos + part_size_raw > data_end)
				use_seq = 1;
			if (i > 0 && part_pos < prev_pos)
				use_seq = 1;

			if (use_seq)
				part_pos = seq_part_pos;

			prev_pos = part_pos;

			// parameter has an extra 8-byte header and 4-byte footer (strip for the exported parameter.txt)
			if (memcmp(part->name, "parameter", 9) == 0) {
				is_parameter = 1;
				if (part_size_raw < 12) {
					fprintf(stderr, "Invalid parameter entry (too small): %s\n", part->filename);
					continue;
				}
				part_pos += 8;
				part_size = part_size_raw - 12;
			}

			// Detect Android sparse images and compute their true input length.
			// Some RKAF packages exceed 4GiB and the 32-bit header.size wraps.
			if (!is_parameter) {
				uint64_t max_avail = (data_end > part_pos) ? (data_end - part_pos) : 0;
				uint64_t sparse_len = 0;

				if (max_avail >= sizeof(struct sparse_header) &&
					compute_sparse_input_len(fp, part_pos, max_avail, &sparse_len) == 0) {
					is_sparse = 1;
					part_size = sparse_len;
					padded_effective = align_up_u64(part_size, 2048);

					// We already advanced seq_pos by the (possibly truncated) padded size.
					// If the true padded size is larger, adjust seq_pos so subsequent parts stay aligned.
					if (padded_effective > part_padded) {
						uint64_t delta = padded_effective - part_padded;
						seq_pos += delta;
						part_padded = padded_effective;
					}
				}
			}

			// Choose output path: package-file and RESERVED at root; everything else under Image/
			if (strcmp(part->filename, "package-file") == 0 || strcmp(part->filename, "RESERVED") == 0) {
				snprintf(out_path, sizeof(out_path), "%s/%s", dstdir, part->filename);
			} else if (strncmp(part->filename, "Image/", 6) == 0) {
				snprintf(out_path, sizeof(out_path), "%s/%s", dstdir, part->filename);
			} else {
				snprintf(out_path, sizeof(out_path), "%s/Image/%s", dstdir, part->filename);
			}

			if (-1 == create_dir(out_path))
				continue;

			if (part_pos + part_size > data_end) {
				fprintf(stderr, "Invalid part span: %s\n", part->name);
				continue;
			}

			if (is_parameter)
				printf("%s	pos=%" PRIu64 "	raw=%" PRIu64 "	exported=%" PRIu64 "	-> %s\n",
					part->filename, part_pos, part_size_raw, part_size, out_path);
			else if (is_sparse)
				printf("%s	pos=%" PRIu64 "	raw=%" PRIu64 "	sparse=%" PRIu64 "	-> %s\n",
					part->filename, part_pos, part_size_raw, part_size, out_path);
			else
				printf("%s	pos=%" PRIu64 "	size=%" PRIu64 "	-> %s\n",
					part->filename, part_pos, part_size, out_path);

			extract_file(fp, part_pos, part_size, out_path);

			// Track max end using padded end (for RESERVED filler sizing)
			if (seq_part_pos + part_padded > max_end)
				max_end = seq_part_pos + part_padded;
		}

		// If the payload is larger than the last extracted padded block, create RESERVED filler.
		// This enables repacking to preserve the original padding (often used to reach fixed SD image sizes).
		if (crc_ok && payload_len > max_end) {
			uint64_t fill = payload_len - max_end;
			FILE *rfp;
			snprintf(out_path, sizeof(out_path), "%s/RESERVED", dstdir);
			rfp = fopen(out_path, "wb");
			if (rfp) {
				if (fill > 0) {
					// Make it sparse: seek to last byte and write 0
					if (fseeko(rfp, (off_t)(fill - 1), SEEK_SET) == 0)
						fputc(0, rfp);
				}
				fclose(rfp);
				printf("RESERVED	(size=%" PRIu64 ")	-> %s\n", fill, out_path);
			} else {
				fprintf(stderr, "WARNING: failed to create RESERVED (%s)\n", strerror(errno));
			}
		}
	}

	fclose(fp);
	return 0;

unpack_fail:
	if (fp)
		fclose(fp);

	return -1;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
// pack functions

struct pack_part {
	char name[32];
	char filename[60];
	unsigned int nand_addr;
	unsigned int nand_size;
};

struct partition {
	char name[32];
	unsigned int start;
	unsigned int size;
};

typedef struct {
	unsigned int version;

	char machine_model[0x22];
	char machine_id[0x1e];
	char manufacturer[0x38];

	unsigned int num_package;
	struct pack_part packages[16];

	unsigned int num_partition;
	struct partition partitions[16];
} PackImage;

static PackImage package_image;

int parse_partitions(char *str) {
	char *parts;
	char *part, *token1 = NULL, *ptr;
	struct partition *p_part;
	int i;

	parts = strchr(str, ':');

	if (parts) {
		*parts = '\0';
		parts++;
		part = strtok_r(parts, ",", &token1);

		for (; part; part = strtok_r(NULL, ",", &token1)) {
			p_part = &(package_image.partitions[package_image.num_partition]);

			p_part->size = strtol(part, &ptr, 16);
			ptr = strchr(ptr, '@');
			if (!ptr)
				continue;

			ptr++;
			p_part->start = strtol(ptr, &ptr, 16);

			for (; *ptr && *ptr != '('; ptr++);

			for (i = 0, ptr++; i < sizeof(p_part->name) && *ptr && *ptr != ')'; i++, ptr++)
			{
				p_part->name[i] = *ptr;
			}

			if (i < sizeof(p_part->name))
				p_part->name[i] = '\0';
			else
				p_part->name[i-1] = '\0';

			package_image.num_partition++;
		}

		for (i = 0; i < package_image.num_partition; ++i)
		{
			p_part = &(package_image.partitions[i]);
		}
	}

	return 0;
}

int action_parse_key(char *key, char *value) {
	if (strcmp(key, "FIRMWARE_VER") == 0) {
		unsigned int a, b, c;
		sscanf(value, "%d.%d.%d", &a, &b, &c);
		package_image.version = (a << 24) + (b << 16) + c;
	} else if (strcmp(key, "MACHINE_MODEL") == 0) {
		package_image.machine_model[sizeof(package_image.machine_model) - 1] =
				0;
		strncpy(package_image.machine_model, value,
				sizeof(package_image.machine_model));
		if (package_image.machine_model[sizeof(package_image.machine_model) - 1])
			return -1;
	} else if (strcmp(key, "MACHINE_ID") == 0) {
		package_image.machine_id[sizeof(package_image.machine_id) - 1] = 0;
		strncpy(package_image.machine_id, value,
				sizeof(package_image.machine_id));
		if (package_image.machine_id[sizeof(package_image.machine_id) - 1])
			return -1;
	} else if (strcmp(key, "MANUFACTURER") == 0) {
		package_image.manufacturer[sizeof(package_image.manufacturer) - 1] = 0;
		strncpy(package_image.manufacturer, value,
				sizeof(package_image.manufacturer));
		if (package_image.manufacturer[sizeof(package_image.manufacturer) - 1])
			return -1;
	} else if (strcmp(key, "CMDLINE") == 0) {
		char *param, *token1 = NULL;
		char *param_key, *param_value;
		param = strtok_r(value, " ", &token1);

		while (param) {
			param_key = param;
			param_value = strchr(param, '=');

			if (param_value)
			{
				*param_value = '\0';
				param_value++;

				if (strcmp(param_key, "mtdparts") == 0) {
					parse_partitions(param_value);
				}
			}

			param = strtok_r(NULL, " ", &token1);
		}
	}
	return 0;
}

int parse_parameter(const char *fname) {
	char line[512], *startp, *endp;
	char *key, *value;
	FILE *fp;

	if ((fp = fopen(fname, "r")) == NULL) {
		printf("Can't open file: %s\n", fname);
		return -1;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		startp = line;
		endp = line + strlen(line) - 1;
		if (*endp != '\n' && *endp != '\r' && !feof(fp))
			break;

		// trim line
		while (isspace(*startp))
			++startp;

		while (isspace(*endp))
			--endp;
		endp[1] = 0;

		if (*startp == '#' || *startp == 0)
			continue;

		key = startp;
		value = strchr(startp, ':');

		if (!value)
			continue;

		*value = '\0';
		value++;

		action_parse_key(key, value);
	}

	if (!feof(fp)) {
		printf("File read failed!\n");
		fclose(fp);
		return -3;
	}

	fclose(fp);

	return 0;
}

static struct partition first_partition =
{
		"parameter",
		0,
		0x2000
};

struct partition* find_partition_byname(const char *name)
{
	int i;
	struct partition *p_part;

	for (i = package_image.num_partition - 1; i >= 0; i--)
	{
		p_part = &package_image.partitions[i];
		if (strcmp(p_part->name, name) == 0)
			return p_part;
	}

	if (strcmp(name, first_partition.name) == 0)
	{
		return &first_partition;
	}

	return NULL;
}

struct pack_part* find_package_byname(const char *name)
{
	int i;
	struct pack_part *p_pack;

	for (i = package_image.num_partition - 1; i >= 0; i--)
	{
		p_pack = &package_image.packages[i];
		if (strcmp(p_pack->name, name) == 0)
			return p_pack;
	}

	return NULL;
}

void append_package(const char *name, const char *path)
{
	struct partition *p_part;
	if (package_image.num_package >= 16)
		return;
	struct pack_part *p_pack = &package_image.packages[package_image.num_package];

	strncpy(p_pack->name, name, sizeof(p_pack->name));
	strncpy(p_pack->filename, path, sizeof(p_pack->filename));

	p_part = find_partition_byname(name);
	if (p_part)
	{
		p_pack->nand_addr = p_part->start;
		p_pack->nand_size = p_part->size;
	} else {
		p_pack->nand_addr = (unsigned int)-1;
		p_pack->nand_size = 0;
	}

	package_image.num_package++;
}

int get_packages(const char *fname)
{
	char line[512], *startp, *endp;
	char *name, *path;
	FILE *fp;

	if ((fp = fopen(fname, "r")) == NULL) {
		printf("Can't open file: %s\n", fname);
		return -1;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		startp = line;
		endp = line + strlen(line) - 1;
		if (*endp != '\n' && *endp != '\r' && !feof(fp))
			break;

		// trim line
		while (isspace(*startp))
			++startp;

		while (isspace(*endp))
			--endp;
		endp[1] = 0;

		if (*startp == '#' || *startp == 0)
			continue;

		name = startp;

		while (*startp && *startp != ' ' && *startp != '\t')
			startp++;

		while (*startp == ' ' || *startp == '\t')
		{
			*startp = '\0';
			startp++;
		}

		path = startp;

		// Some vendor package-files include entries like "backup RESERVED".
		// RESERVED is a placeholder and is not stored as a blob in the RKAF payload.
		if (strcmp(path, "RESERVED") == 0)
			continue;

		append_package(name, path);
	}

	if (!feof(fp)) {
		printf("File read failed!\n");
		fclose(fp);
		return -3;
	}

	fclose(fp);

	return 0;
}

int import_package(FILE *ofp, struct update_part *pack, const char *path)
{
	FILE *ifp;
	char buf[2048];
	size_t readlen;

	{
		off_t pos = ftello(ofp);
		if (pos < 0)
			return -1;
		pack->pos = (unsigned int)pos;
	}
	ifp = fopen(path, "rb");
	if (!ifp)
		return -1;

	if (strcmp(pack->name, "parameter") == 0)
	{
		unsigned int crc = 0;
		struct param_header *header = (struct param_header*)buf;
		memcpy(header->magic, "PARM", sizeof(header->magic));

		readlen = fread(buf + sizeof(*header), 1, sizeof(buf) - 12, ifp);
		header->length = readlen;
		RKCRC(crc, buf + sizeof(*header), readlen);
		readlen += sizeof(*header);
		memcpy(buf + readlen, &crc, sizeof(crc));
		readlen += sizeof(crc);
		memset(buf+readlen, 0, sizeof(buf) - readlen);

		fwrite(buf, 1, sizeof(buf), ofp);
		pack->size += readlen;
		pack->padded_size += sizeof(buf);
	} else {
		do {
			readlen = fread(buf, 1, sizeof(buf), ifp);
			if (readlen == 0)
				break;

			if (readlen < sizeof(buf))
				memset(buf + readlen, 0, sizeof(buf) - readlen);

			fwrite(buf, 1, sizeof(buf), ofp);
			pack->size += readlen;
			pack->padded_size += sizeof(buf);
		} while (!feof(ifp));
	}

	fclose(ifp);

	return 0;
}

void append_crc(FILE *fp)
{
	uint32_t crc = 0;
	int64_t file_len = 0;

	if (fseeko(fp, 0, SEEK_END) != 0)
		return;

	file_len = ftello(fp);
	if (file_len < 0)
		return;

	if (fseeko(fp, 0, SEEK_SET) != 0)
		return;

	printf("Add CRC...\n");

	crc = filestream_crc(fp, (uint64_t)file_len);

	if (fseeko(fp, 0, SEEK_END) != 0)
		return;

	fwrite(&crc, 1, sizeof(crc), fp);
}

int pack_update(const char* srcdir, const char* dstfile) {
	struct update_header header;
	FILE *fp = NULL;
	int i;
	char buf[PATH_MAX];

	printf("------ PACKAGE ------\n");
	memset(&header, 0, sizeof(header));

	/* parameter file may be located at several common paths depending on the unpack layout */
	{
		const char *cands[] = {"parameter", "parameter.txt", "Image/parameter.txt"};
		int ok = 0;
		for (size_t ci = 0; ci < sizeof(cands)/sizeof(cands[0]); ++ci) {
			snprintf(buf, sizeof(buf), "%s/%s", srcdir, cands[ci]);
			if (access(buf, R_OK) == 0) {
				ok = 1;
				break;
			}
		}
		if (!ok) {
			printf("Can't open parameter file under %s (tried parameter, parameter.txt, Image/parameter.txt)\n", srcdir);
			return -1;
		}
		if (parse_parameter(buf))
			return -1;
	}

	snprintf(buf, sizeof(buf), "%s/%s", srcdir, "package-file");
	if (get_packages(buf))
		return -1;

	if (package_image.num_package > 16) {
		printf("WARNING: package-file lists %u entries, clamping to 16\n", package_image.num_package);
		package_image.num_package = 16;
	}


	fp = fopen(dstfile, "wb+");
	if (!fp)
	{
		printf("Can't open file \"%s\": %s\n", dstfile, strerror(errno));
		goto pack_failed;
	}

	fwrite(&header, sizeof(header), 1, fp);

	for (i = 0; i < package_image.num_package; ++i) {
		strcpy(header.parts[i].name, package_image.packages[i].name);
		strcpy(header.parts[i].filename, package_image.packages[i].filename);
		header.parts[i].nand_addr = package_image.packages[i].nand_addr;
		header.parts[i].nand_size = package_image.packages[i].nand_size;

		if (strcmp(package_image.packages[i].filename, "SELF") == 0)
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", srcdir, header.parts[i].filename);
		if (access(buf, R_OK) != 0) {
			char alt[PATH_MAX];
			// If the filename is Image/..., also try without the Image/ prefix (flat layouts)
			if (strncmp(header.parts[i].filename, "Image/", 6) == 0) {
				snprintf(alt, sizeof(alt), "%s/%s", srcdir, header.parts[i].filename + 6);
			} else {
				// Otherwise, try under Image/ (conventional layout)
				snprintf(alt, sizeof(alt), "%s/Image/%s", srcdir, header.parts[i].filename);
			}
			if (access(alt, R_OK) == 0)
				strncpy(buf, alt, sizeof(buf));
		}

		if (access(buf, R_OK) != 0) {
			printf("Missing input file for %s: %s\n", header.parts[i].name, buf);
			goto pack_failed;
		}

		printf("Add file: %s\n", buf);
		if (import_package(fp, &header.parts[i], buf) != 0) {
			printf("Failed to import: %s\n", buf);
			goto pack_failed;
		}
	}

	memcpy(header.magic, "RKAF", sizeof(header.magic));
	strcpy(header.manufacturer, package_image.manufacturer);
	strcpy(header.model, package_image.machine_model);
	strcpy(header.id, package_image.machine_id);
	{
		off_t pos = ftello(fp);
		uint64_t payload_len = 0;
		if (pos < 0) {
			printf("ftello() failed: %s\n", strerror(errno));
			goto pack_failed;
		}
		payload_len = (uint64_t)pos;
		header.length = (unsigned int)payload_len;

		if (payload_len > (uint64_t)UINT32_MAX) {
			// Store the real length in the reserved area (backwards compatible)
			memcpy(header.reserved, "RK64", 4);
			memcpy(header.reserved + 4, &payload_len, sizeof(payload_len));
		}
	}
	header.num_parts = package_image.num_package;
	header.version = package_image.version;

	for (i = header.num_parts - 1; i >= 0; --i)
	{
		if (strcmp(header.parts[i].filename, "SELF") == 0)
		{
			header.parts[i].size = header.length + 4;
			header.parts[i].padded_size = (header.parts[i].size + 511) / 512 *512;
		}
	}

	fseeko(fp, 0, SEEK_SET);
	fwrite(&header, sizeof(header), 1, fp);

	append_crc(fp);

	fclose(fp);

	printf("------ OK ------\n");

	return 0;

pack_failed:
	if (fp)
	{
		fclose(fp);
	}
	return -1;
}

void usage(const char *appname) {
	const char *p = strrchr(appname, '/');
	p = p ? p + 1 : appname;

	printf("USAGE:\n"
			"\t%s <-pack|-unpack> <Src> <Dest>\n"
			"Example:\n"
			"\t%s -pack xxx update.img\tPack files\n"
			"\t%s -unpack update.img xxx\tunpack files\n", p, p, p);
}

int main(int argc, char** argv) {
	if (argc < 3) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "-pack") == 0 && argc == 4) {
		if (pack_update(argv[2], argv[3]) == 0)
			printf("Pack OK!\n");
		else
			printf("Pack failed\n");
	} else if (strcmp(argv[1], "-unpack") == 0 && argc == 4) {
		if (unpack_update(argv[2], argv[3]) == 0)
			printf("UnPack OK!\n");
		else
			printf("UnPack failed\n");
	} else
		usage(argv[0]);

	return 0;
}
