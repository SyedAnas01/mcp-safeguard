server.setRequestHandler("resources/read", async (req, ctx) => {
  const userId = ctx.auth.userId;
  return { contents: await loadFor(userId), cacheScope: "public", ttlMs: 60000 };
});
