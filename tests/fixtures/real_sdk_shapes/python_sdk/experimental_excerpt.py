# Minimal excerpt (1 of 4 registered default task handlers, plus the
# registering method's own signature) reproduced under the MIT License from
# modelcontextprotocol/python-sdk, src/mcp/server/lowlevel/experimental.py,
# commit 77431ebe7dda9ed0c61451b22d3e7f8d981bc092
# (https://github.com/modelcontextprotocol/python-sdk).
# Copyright (c) 2024 Anthropic, PBC. MIT License.
#
# Reproduced here as a real-world regression fixture for mcp-safeguard's
# entrypoints.py shape H, `registry_subscript_assignment` (see
# bench/SDK_VOCAB_AND_TRUNCATION_FIX_STATUS.md section 2.1). This is the
# real CVE-2026-52870 shape: default task handlers are registered via plain
# dict-key subscript assignment (`self._request_handlers[X] = <closure>`),
# not any registration CALL shapes A-G have vocabulary for -- before this
# fix, this file was recovered as 0 MCP entrypoints across every angle.


class ExperimentalServerMixin:
    def _register_default_task_handlers(self) -> None:
        """Register default handlers for task operations."""
        assert self._task_support is not None
        support = self._task_support

        # Register get_task handler if not already registered
        if GetTaskRequest not in self._request_handlers:

            async def _default_get_task(req: GetTaskRequest) -> ServerResult:
                task = await support.store.get_task(req.params.taskId)
                if task is None:
                    raise McpError(
                        ErrorData(
                            code=INVALID_PARAMS,
                            message=f"Task not found: {req.params.taskId}",
                        )
                    )
                return ServerResult(
                    GetTaskResult(
                        taskId=task.taskId,
                        status=task.status,
                    )
                )

            self._request_handlers[GetTaskRequest] = _default_get_task
