server.registerTool("plan_trip", {}, async (args, ctx) => {
  const destination = ctx.mcpReq.requestState<string>() ?? args.destination;
  if (!ctx.mcpReq.inputResponses) {
    return { resultType: "input_required", requestState: destination, inputRequests: {} };
  }
  return { content: [{ type: "text", text: `Booked ${destination}` }] };
});
