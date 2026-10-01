# Codex: model chính theo session, subagent dùng Luna

## Thiết kế và phạm vi đã thống nhất

Giữ nguyên model mà người dùng chọn khi bắt đầu session. Chỉ định
`gpt-6-luna` / reasoning `high` cho subagent, tối đa hai luồng con mở đồng thời.
Không đặt model, reasoning, provider, service tier, profile hoặc quyền của
agent chính trong `.codex/config.toml`.

Đây là cấu hình local-client của Codex, bổ sung chuyên môn cho các lượt khảo sát.
`AGENTS.md`, `.agent/policies/` và các canonical skill vẫn có thẩm quyền;
`.codex/` không thay thế chúng. Không sửa các bản sinh trong `.agents/` hoặc
`.claude/`. Không thay đổi ứng dụng PgDog, CI, runtime review hoặc cấu hình provider
trong `.agent/`.

Các custom role đều có mặc định `read-only`:

| Role | Phạm vi |
| --- | --- |
| `pgdog_core` | Rust workspace, PostgreSQL protocol, pooling và routing |
| `pgdog_security` | Auth, TLS, credential và log của proxy |
| `pgdog_ci` | Workflow, log, Cargo manifest và cấu hình test/container |
| `agent_runtime` | CLI `.agent/`, adapter, memory và quality gate |

Các role nhận phần việc hẹp, trả bằng chứng `file:dòng` và báo cáo khoảng
300–500 từ. Agent chính xác minh và tổng hợp; không giao cả bốn role cho mọi câu hỏi.
`[agents] enabled = false` trong từng role tắt công cụ multi-agent của phiên con.
Không tự nâng model, thêm provider hoặc bỏ qua lỗi quyền truy cập model.

## Trình tự triển khai và kiểm tra

1. Kiểm tra nhánh gốc và bảo toàn các file/cấu hình hiện có.
2. Kiểm thử hợp đồng cấu hình trước khi thêm năm file TOML; xác nhận thất bại
   vì chưa có cấu hình, sau đó thêm cấu hình và chạy lại.
3. Kiểm tra diff chỉ có `.codex/`, không có khóa ghi đè session chính.
4. Mở PR để CI và review theo policy repo; không tự merge hoặc xuất review package.
5. Thử một subagent trong phiên Codex mới, rồi mới mở rộng phạm vi sử dụng.

## Sử dụng

Sau khi lấy nhánh có cấu hình này về bản clone, mở **phiên Codex mới** tại root
repository và chọn model chính theo cách vẫn dùng. Không cần chọn Luna cho
phiên chính hoặc sửa `~/.codex/config.toml`.

Project config chỉ được nạp khi dự án được tin cậy. Dùng `/debug-config` để kiểm
tra lớp cấu hình trong client hỗ trợ lệnh này. Tài khoản/client/workspace phải có
quyền dùng `gpt-6-luna`; file TOML không cấp quyền model. Nếu bị từ chối, báo lỗi
và dừng phần giao việc đó, không tự chuyển sang model đắt hơn.

Ví dụ cho một nhiệm vụ CI:

```text
Giữ nguyên model của session chính.
Chỉ tạo pgdog_ci để phân tích workflow và log liên quan đến lỗi tôi cung cấp.
Dùng model/effort đã ghim trong custom role; không tạo đủ bốn agent theo thói quen.
Chỉ thêm pgdog_core nếu cần đối chiếu mã Rust hoặc Cargo manifest.
Không tự nâng model hoặc fallback khi Luna không khả dụng.
Các subagent chỉ đọc, trả bằng chứng ngắn gọn; agent chính xác minh phần quan trọng.
Tuân thủ AGENTS.md. Chưa sửa file, chạy test/build/container, rerun CI hoặc push.
```

Smoke test tối thiểu:

```text
Giữ model chính đang dùng. Tạo đúng một custom subagent pgdog_ci.
Giao nó đọc applications/pgdog/Cargo.toml và báo tối đa 120 từ về workspace.
Không đọc rộng toàn repo, sửa file, chạy test/build/container hoặc tạo agent lồng.
Dùng gpt-6-luna / high theo role. Nếu không khả dụng thì báo lỗi, không fallback.
Agent chính chờ kết quả; không dùng lời tự nhận model của agent làm bằng chứng.
```

Dùng `/agent` để xem luồng con; đối chiếu model thực tế trong metadata/status của
client. Không coi chỉ dẫn hoặc câu trả lời của model là bằng chứng đã chạy đúng model.

## Kiểm thử offline

Yêu cầu Python 3.11+. Chạy tại root repo:

```bash
python3 -m unittest discover -s .codex/tests -v
```

Các test đọc chính năm file TOML đã commit; kiểm tra khóa session chính không bị
ghi đè, bốn role, model/effort, mặc định chỉ đọc và tắt multi-agent lồng nhau.
Không gọi Codex/API, dùng credential, kết nối mạng, build hoặc sửa ứng dụng.
Đây là kiểm thử cấu hình, **không phải** kiểm thử runtime hoặc chứng nhận quyền model.

Các kiểm tra của repo vẫn phải được thực hiện ở môi trường đầy đủ:

```bash
./scripts/agent adapters check
./scripts/agent verify quick --json
# Trước merge, hoàn tất review độc lập và bằng chứng cần thiết, rồi:
./scripts/agent verify merge --json
```

Một kết quả tĩnh đạt không thay thế các gate này. Kiểm thử trong `.codex/tests/`
là lệnh riêng, không tự động được thêm vào workflow hiện có bởi PR này.

## Giới hạn và tác động

- Hai luồng là giới hạn đồng thời, không phải hạn mức tổng token hay chi phí.
  Thu hẹp phạm vi và đầu ra mới tránh công việc trùng lặp; chưa đo tiết kiệm thực tế.
- Model/effort ghim trong custom role có ưu tiên hơn mặc định. Các role khác,
  cấu hình cá nhân và giá trị spawn tường minh có thể có cách phân giải khác;
  mặc định chung không phải khóa cứng cho mọi agent.
- Subagent kế thừa môi trường/quyền của phiên chính; lựa chọn quyền tương tác
  có thể ghi đè mặc định `read-only`. Không bật Full access để khắc phục lỗi model.
- Tắt công cụ multi-agent lồng nhau không phải hàng rào chống mọi lệnh shell/MCP
  hoặc egress. Tuân thủ quyền và giới hạn môi trường thực tế.
- Không thêm endpoint, provider hay credential; các model call dùng phiên Codex
  đã được người dùng cho phép. Không tự chạy provider review hoặc gửi source
  sang dịch vụ khác. Review cross-provider vẫn cần phê duyệt manifest theo repo.
- Nhiều subagent Codex không phải review độc lập bằng provider khác. Không dùng
  chúng để đánh dấu gate review đã đạt.

Hoàn tác bằng cách revert commit cấu hình qua một PR riêng. Không cần đổi model
cá nhân, xóa session hoặc chạm tới mã PgDog; bảo toàn chỉnh sửa local trước khi đổi nhánh.

## Tài liệu đối chiếu

- Custom agents và thứ tự ưu tiên: https://developers.openai.com/codex/subagents
- Các khóa cấu hình: https://developers.openai.com/codex/config-reference
- Model và reasoning hỗ trợ: https://developers.openai.com/api/docs/models/gpt-6-luna

Quyền dùng model và kết quả chạy thực tế phải được xác minh trong phiên của người dùng.
