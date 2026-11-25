const server = new Server(info, { requestState: { verify: hmacVerify } });
server.registerTool("plan_trip", {}, async (args, ctx) => {
  const destination = ctx.mcpReq.requestState<string>() ?? args.destination;
  return { resultType: "input_required", requestState: hmacSign(destination, ctx) };
});
