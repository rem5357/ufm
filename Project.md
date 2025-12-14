# UFM Project Status

## Session: 2025-12-13 - P2P Networking & Transfer Debugging

### Summary
Debugged and fixed multiple issues with P2P networking between UFM nodes (Falcon on Windows, Goldshire on Linux). Successfully implemented remote archive creation and improved transfer functionality.

### Nodes
- **Goldshire** (Linux): 192.168.86.112:9847 - Acts as bootstrap node and daemon
- **Falcon** (Windows): Claude Desktop MCP client

### What Was Accomplished

#### 1. Remote Archive Creation (Build 106)
- Added `node` parameter to all archive tools:
  - `ufm_archive_create`
  - `ufm_archive_list`
  - `ufm_archive_read`
  - `ufm_archive_extract`
- Added `maybe_route_remote()` calls to archive handlers
- **Result**: Can now create zip files on remote nodes via MCP tools

#### 2. Transfer Pull Fix (Build 109)
- **Bug**: Pull transfers (`source_node: 1, dest_node: 0`) returned "Node not found: id 1"
- **Cause**: `handle_transfer` was including `"node": args["source_node"]` in remote_args, causing the remote to try routing to a non-existent node
- **Fix**: Removed node parameter from remote_args - we want `ufm_read` to execute locally on the remote
- Also fixed response parsing - `ufm_read` returns content directly, not a JSON object

#### 3. Security Path Normalization (Build 112)
- **Bug**: Paths like `C:\Users\rober\Downloads` were rejected as "outside allowed roots" even when home dir was allowed
- **Cause**: `allowed_roots` weren't normalized, and `path.starts_with(root)` comparison failed due to different path formats
- **Fix**:
  - Added `normalize_root()` to canonicalize allowed roots when stored
  - Made `is_within_allowed_roots()` case-insensitive on Windows

#### 4. Status Endpoint Improvements (Build 115)
- **Problem**: Claude Desktop guessed wrong username ("mithroll" instead of "rober") when constructing paths
- **Fix**: Added to `ufm_status` response:
  - `username` - current logged-in user
  - `home_dir` - full path to home directory
  - `downloads_dir` - full path to Downloads folder
- Now clients can query these instead of guessing

### Lessons Learned

1. **Node parameter stripping**: When routing tool requests to remote nodes, the `node` parameter must be stripped from args to prevent routing loops. The remote executes the tool locally.

2. **Path normalization is critical**: On Windows, paths must be:
   - Canonicalized for consistent comparison
   - Compared case-insensitively
   - Both the checked path AND the allowed roots must be normalized

3. **Don't assume usernames**: MCP clients shouldn't hardcode or guess usernames. Expose paths via status/info endpoints.

4. **Bincode + serde_json::Value don't mix**: Earlier in the session (pre-summary), discovered bincode can't serialize `serde_json::Value`. Solution was to use `params_json: String` and serialize JSON separately.

5. **Session handling matters**: Peer connections need to stay open and handle multiple messages, not just accept and close.

### Outstanding Problems / TODOs

#### High Priority
- [ ] **Pull transfers still use base64**: Pull operations (`!source_is_local && dest_is_local`) use `ufm_read` with base64 encoding through tool responses. Should implement streaming pull like we have for push.
- [x] **Test the full transfer flow**: ~~With build 115, Falcon needs to update and retry the transfer to verify everything works end-to-end.~~ DONE - 67KB transfer successful.
- [ ] **Eliminate bootstrap nodes**: Make node detection completely dynamic. No hardcoded bootstrap addresses - nodes should discover each other automatically via mDNS or other zero-config methods.

#### Medium Priority
- [ ] **Remote-to-remote transfers**: Currently returns "not yet implemented". Would need relay or direct P2P negotiation.
- [ ] **Transfer progress/status**: `handle_transfer_status` is a placeholder. Need to expose `TransferManager` in `ToolState` for real tracking.
- [ ] **Security config UX**: Users have to manually edit config.toml to add allowed paths like `D:\`. Consider a tool or flag to add paths.

#### Low Priority
- [ ] Clean up unused code warnings (67 warnings in build)
- [ ] The `TransferManager` methods (`start_outgoing`, `get_next_chunk`, etc.) are implemented but never used - the streaming uses direct `stream_file_to_peer` instead

### Key Files Modified

- `src/tools.rs` - Archive tool definitions, transfer handlers, status endpoint
- `src/security.rs` - Path normalization and Windows case-insensitivity
- `src/network/peer.rs` - Session handling, streaming transfers (earlier session)
- `src/network/protocol.rs` - Changed to `params_json: String` (earlier session)

### Build History (This Session)
- Build 106: Remote archive tools with node parameter
- Build 109: Transfer pull node routing fix
- Build 112: Security path normalization
- Build 115: Status endpoint with username/home_dir/downloads_dir

### Testing Notes

The test file `Faulty.zip` was successfully created on Goldshire at:
```
/home/mithroll/Projects/Faulty/Faulty.zip
```

Contains 11 files (8 .md, 3 .txt) from the Faulty project root.

To test transfer on Falcon after updating to build 115:
```
ufm_status  # Check downloads_dir
ufm_transfer(
  source_path="/home/mithroll/Projects/Faulty/Faulty.zip",
  source_node="goldshire",
  dest_path="<downloads_dir from status>/Faulty.zip"
)
```
