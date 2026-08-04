---
name: "cloud-storage"
description: "Cloud Storage Misconfiguration Testing"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "cloud", "s3", "azure-blob", "gcs", "bucket", "storage", "cors"]
trigger_patterns:
  - "/cloud-storage"
  - "test s3 bucket"
  - "test cloud storage"
  - "test azure blob"
  - "test gcs bucket"
  - "bucket misconfiguration"
  - "public bucket"
---

# Cloud Storage Misconfiguration Testing

Test AWS S3 buckets, Azure Blob Storage containers, and Google Cloud Storage
buckets for public listing, unauthorized read/write, overly permissive ACLs,
pre-signed URL abuse, and CORS misconfiguration.

## Scope and preconditions

Applies when the target application uses cloud storage for assets, uploads,
backups, or data sharing. Storage URLs are discovered through page source,
API responses, JavaScript files, or DNS records.

It does **not** cover: cloud IAM policy review (requires console access),
server-side storage logic (use `file-upload`), or general cloud penetration
testing.

## Rules of engagement

- NEVER download, read, or exfiltrate real user data from buckets. Confirm
  access by listing a few file names or reading only test files you created.
- NEVER delete or overwrite existing files. If write access exists, upload a
  clearly marked test file (void-test-<random>.txt) and record it for cleanup.
- Record every finding with add_pentest_finding.
- In mode `ask`: confirm the misconfiguration exists and stop.

## Workflow

- [ ] 1. Discover storage URLs
- [ ] 2. Identify the storage provider
- [ ] 3. Test listing (anonymous)
- [ ] 4. Test read access
- [ ] 5. Test write access
- [ ] 6. Check ACLs
- [ ] 7. Analyze pre-signed URLs
- [ ] 8. Test CORS configuration

## Step 1: Discover storage URLs

### Actions

Use search_responses and get_scripts to find cloud storage references:

| Pattern | Provider |
|---------|----------|
| `s3.amazonaws.com` | AWS S3 |
| `s3-<region>.amazonaws.com` | AWS S3 (region-specific) |
| `<bucket>.s3.amazonaws.com` | AWS S3 (virtual-hosted) |
| `storage.googleapis.com/<bucket>` | Google Cloud Storage |
| `<bucket>.storage.googleapis.com` | GCS (virtual-hosted) |
| `<account>.blob.core.windows.net/<container>` | Azure Blob Storage |
| `<account>.blob.core.windows.net` | Azure Blob Storage |

Also check:
- DNS CNAME records pointing to storage services
- JavaScript source maps referencing storage URLs
- API responses containing signed URLs
- Error pages leaking bucket names

### Common URL patterns to search for

Use search_responses with:
- `\.s3\.` or `s3\.amazonaws`
- `blob\.core\.windows\.net`
- `storage\.googleapis\.com`
- `cloudfront\.net` (may front an S3 bucket)

## Step 2: Identify provider and extract details

| Provider | URL format | Key info |
|----------|-----------|----------|
| AWS S3 | `https://bucket.s3.region.amazonaws.com/key` | bucket name, region |
| Azure Blob | `https://account.blob.core.windows.net/container/blob` | account, container |
| GCS | `https://storage.googleapis.com/bucket/object` | bucket name |

## Step 3: Test listing (anonymous)

### AWS S3

Use send_request:
```
GET / HTTP/1.1
Host: <bucket>.s3.amazonaws.com
```

Or:
```
GET /<bucket> HTTP/1.1
Host: s3.amazonaws.com
```

If the response contains `<ListBucketResult>` with `<Key>` elements, the bucket
allows anonymous listing.

### Azure Blob

```
GET /<container>?restype=container&comp=list HTTP/1.1
Host: <account>.blob.core.windows.net
```

If the response contains `<EnumerationResults>` with `<Blob>` elements, listing
is enabled.

### GCS

```
GET /storage/v1/b/<bucket>/o HTTP/1.1
Host: storage.googleapis.com
```

If the response is a JSON array of objects, listing is enabled.

## Step 4: Test read access

### Actions

If listing succeeded, try reading a file:

**AWS S3:**
```
GET /<key> HTTP/1.1
Host: <bucket>.s3.amazonaws.com
```

**Azure Blob:**
```
GET /<container>/<blob> HTTP/1.1
Host: <account>.blob.core.windows.net
```

**GCS:**
```
GET /storage/v1/b/<bucket>/o/<object>?alt=media HTTP/1.1
Host: storage.googleapis.com
```

If the file content is returned without authentication, anonymous read is
confirmed.

### What to look for in file listings

| File pattern | Risk |
|-------------|------|
| `.env`, `config.json`, `credentials` | Credential exposure (Critical) |
| Database backups (`.sql`, `.dump`) | Data breach (Critical) |
| Log files | Information disclosure |
| User uploads (PII, documents) | Data breach |
| Source code (`.zip`, `.tar.gz`) | IP exposure |
| `.git/` directory | Full source history |

Do NOT read these files. Note their existence and report.

## Step 5: Test write access

### Actions

Attempt to upload a benign test file:

**AWS S3:**
```
PUT /void-test-<random>.txt HTTP/1.1
Host: <bucket>.s3.amazonaws.com
Content-Type: text/plain

This is a security test file. Please delete. Contact: <your-email>
```

**Azure Blob:**
```
PUT /<container>/void-test-<random>.txt HTTP/1.1
Host: <account>.blob.core.windows.net
x-ms-blob-type: BlockBlob
Content-Type: text/plain

This is a security test file. Please delete. Contact: <your-email>
```

**GCS:**
```
POST /upload/storage/v1/b/<bucket>/o?uploadType=media&name=void-test-<random>.txt HTTP/1.1
Host: storage.googleapis.com
Content-Type: text/plain

This is a security test file. Please delete. Contact: <your-email>
```

If the upload succeeds (200/201), anonymous write is confirmed. Record the
file path for cleanup.

### Impact of write access

| Scenario | Impact |
|----------|--------|
| Bucket serves static website assets (JS/CSS) | Stored XSS via script replacement |
| Bucket used for application configuration | Full application compromise |
| Bucket used for user uploads | Malware distribution |
| Bucket used for backups | Data manipulation |

## Step 6: Check ACLs

### AWS S3

```
GET /<bucket>?acl HTTP/1.1
Host: s3.amazonaws.com
```

Look for:
- `<Grant>` to `AllUsers` (public access)
- `<Grant>` to `AuthenticatedUsers` (any AWS account)
- `FULL_CONTROL` to `AllUsers` (Critical — read + write + ACL change)

### Azure Blob

Check the `x-ms-blob-public-access` header in responses:
- `blob`: individual blobs are public
- `container`: listing + blob access is public
- Missing: private (default)

### GCS

```
GET /storage/v1/b/<bucket>/iam HTTP/1.1
Host: storage.googleapis.com
```

Look for `allUsers` or `allAuthenticatedUsers` in IAM bindings.

## Step 7: Analyze pre-signed URLs

If the application uses pre-signed/SAS URLs for access:

### What to check

Use search_responses to find signed URLs and analyze their parameters:

**AWS S3 pre-signed:**
- `X-Amz-Expires`: how long the URL is valid (> 24h is risky)
- `X-Amz-Algorithm`: should be AWS4-HMAC-SHA256
- Can the signature parameters be removed? (falls back to bucket ACL)

**Azure SAS:**
- `se=`: expiry time (long-lived tokens are risky)
- `sp=`: permissions (r=read, w=write, d=delete, l=list)
- `sr=`: scope (b=blob, c=container — container scope is broader)

**GCS signed:**
- `Expires=`: timestamp
- `X-Goog-SignedHeaders`: which headers are signed

### Findings

| Condition | Severity |
|-----------|----------|
| Pre-signed URL valid for > 7 days | Medium |
| Pre-signed URL grants write access | High |
| SAS token with container-level list+read | High |
| Signature can be removed and access still works | Critical |

## Step 8: Test CORS configuration

### Actions

Use send_request with an Origin header:

```
OPTIONS /<key> HTTP/1.1
Host: <bucket>.s3.amazonaws.com
Origin: https://evil.com
Access-Control-Request-Method: GET
```

Check the response for:
- `Access-Control-Allow-Origin: *` — any origin can read (risky if authenticated)
- `Access-Control-Allow-Origin: https://evil.com` — wildcard reflection
- `Access-Control-Allow-Credentials: true` — cookies sent cross-origin

If `Allow-Origin: *` AND `Allow-Credentials: true`, this is a critical CORS
misconfiguration allowing cross-origin data theft.

## Severity reference

| Finding | Severity |
|---------|----------|
| Public write access to bucket serving application assets | Critical |
| Public read access to credentials/secrets/backups | Critical |
| Public bucket listing with sensitive file names | High |
| Anonymous read access to user data | High |
| Overly permissive ACL (AllUsers: FULL_CONTROL) | Critical |
| CORS allows any origin with credentials | High |
| Long-lived pre-signed URLs with write access | High |
| Public listing but only non-sensitive static assets | Medium |
| Pre-signed URLs with read-only, short expiry | Low |

## Known false positives

- A bucket is intentionally public (static website hosting for public assets) —
  confirm with the client before reporting.
- CDN-fronted bucket that requires signed cookies — the bucket itself may be
  public but access is controlled at the CDN layer.
- A 403 on listing does not mean individual objects are private — test specific
  object paths separately.
- Pre-signed URLs are expected for file downloads — only report if the expiry
  is excessive or permissions are too broad.

## Tooling note

This methodology is designed for the Void panel tools (send_request,
compare_responses, search_responses, get_endpoints, eval_page, get_scripts,
add_pentest_finding). These are browser-extension APIs, not shell commands.
Do not attempt to run CLI tools like aws-cli, az, or gsutil.
