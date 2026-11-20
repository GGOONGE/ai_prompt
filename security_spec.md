# Security Specification: 나의 AI 프롬프트 창고

## 1. Data Invariants
- Read access (`get`, `list`) on `/prompts` is public so guests can browse, search, filter, and copy prompts without logging in.
- Write access (`create`, `update`, `delete`) on `/prompts/{promptId}` is strictly restricted to the verified admin account (`eajs040807@gmail.com` with `request.auth.token.email_verified == true`).
- Every document in `/prompts/{promptId}` must have a valid alphanumeric/hyphen/underscore `promptId` (`^[a-zA-Z0-9_\-]+$`, max 128 chars).
- Every prompt document must contain strictly and only the 4 keys: `title`, `category`, `content`, `createdAt`.
- `title` must be a non-empty string up to 120 characters.
- `category` must strictly belong to the allowed enum: `['사진 합성', '스타일 변환', '캐릭터·포스터']`.
- `content` must be a non-empty string up to 20,000 characters (supporting prompts over 1,000 characters while preventing 1MB payload exhaustion).
- `createdAt` must equal `request.time` upon creation and remain strictly immutable upon update.
- No unmodeled collections or shadow fields are permitted anywhere in the database (default-deny safety net on `/{document=**}`).

## 2. Adversarial Test Payloads ("Dirty Dozen")
1. **Shadow Field Injection on Create**: `{ title: "T", category: "사진 합성", content: "C", createdAt: serverTimestamp, isAdmin: true }` -> `PERMISSION_DENIED`
2. **Missing Required Field (`content`)**: `{ title: "T", category: "사진 합성", createdAt: serverTimestamp }` -> `PERMISSION_DENIED`
3. **Invalid Category Enum**: `{ title: "T", category: "무단 분류", content: "C", createdAt: serverTimestamp }` -> `PERMISSION_DENIED`
4. **Empty Title**: `{ title: "", category: "사진 합성", content: "C", createdAt: serverTimestamp }` -> `PERMISSION_DENIED`
5. **Title Oversize (>120 chars)**: `{ title: "a".repeat(121), category: "사진 합성", content: "C", createdAt: serverTimestamp }` -> `PERMISSION_DENIED`
6. **Content Oversize (>20000 chars)**: `{ title: "T", category: "사진 합성", content: "a".repeat(20001), createdAt: serverTimestamp }` -> `PERMISSION_DENIED`
7. **Forged Client Timestamp on Create**: `{ title: "T", category: "사진 합성", content: "C", createdAt: pastTimestamp }` -> `PERMISSION_DENIED`
8. **Wrong Type for `content` (number/map)**: `{ title: "T", category: "사진 합성", content: 12345, createdAt: serverTimestamp }` -> `PERMISSION_DENIED`
9. **Immutable `createdAt` Mutation on Update**: Updating `createdAt` to a new timestamp -> `PERMISSION_DENIED`
10. **Shadow Field Injection on Update**: Updating `{ title: "New", extraFlag: true }` -> `PERMISSION_DENIED`
11. **Path ID Poisoning**: Creating `/prompts/bad$id%00` -> `PERMISSION_DENIED`
12. **Unmodeled Collection Access**: Writing to `/users/u1` or `/admin/config` -> `PERMISSION_DENIED`
