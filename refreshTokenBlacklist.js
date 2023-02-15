const MAX_TOKEN_AGE = 3600 * 1000; // Max token age in milliseconds (1 hour)

// Function to remove expired tokens from the blacklist
const pruneBlacklistedTokens = () => {
  const now = Date.now();
  blacklistedTokens.forEach((token, tokenTime) => {
    if (now - tokenTime > MAX_TOKEN_AGE) {
      blacklistedTokens.delete(token);
    }
  });
};

// Schedule the task to run every hour
setInterval(pruneBlacklistedTokens, 3600 * 1000);
