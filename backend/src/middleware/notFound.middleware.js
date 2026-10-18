const { contentSecurityPolicy } = require('helmet');

const notFoundContentSecurityPolicy = contentSecurityPolicy({
  useDefaults: false,
  directives: {
    defaultSrc: ["'none'"],
    frameAncestors: ["'none'"],
    formAction: ["'none'"],
  },
});

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[character]);
}

function notFoundHandler(req, res, next) {
  res.status(404).json({
    message: `API route not found: ${req.originalUrl}`,
  });
}

function htmlNotFoundHandler(req, res, next) {
  notFoundContentSecurityPolicy(req, res, (error) => {
    if (error) {
      return next(error);
    }

    const message = escapeHtml(`Cannot ${req.method} ${req.path}`);
    return res.status(404).type('html').send(
      `<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Error</title>\n</head>\n<body>\n<pre>${message}</pre>\n</body>\n</html>\n`
    );
  });
}

module.exports = {
  htmlNotFoundHandler,
  notFoundHandler,
};
