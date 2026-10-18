function errorHandler(err, req, res, next) {
  const requestedStatus = err.statusCode;
  const statusCode = Number.isInteger(requestedStatus) && requestedStatus >= 400 && requestedStatus < 500
    ? requestedStatus
    : 500;

  res.status(statusCode).json({
    message: statusCode < 500 ? err.message : 'Internal server error',
  });
}

module.exports = {
  errorHandler,
};
