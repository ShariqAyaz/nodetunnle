const MAX_TOKEN_AGE = 3600 * 1000; // 1 hr

// Remove expire entry in the blacklist tabl
const pruneBlacklistedTokens = () => {
  const now = Date.now();
  blacklistedTokens.forEach((token, tokenTime) => {
    if (now - tokenTime > MAX_TOKEN_AGE) {
      blacklistedTokens.delete(token);
    }
  });
};

setInterval(pruneBlacklistedTokens, 3600 * 1000);
