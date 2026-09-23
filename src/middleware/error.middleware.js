export function errorHandler(
  error,
  req,
  res,
  next,
) {
  if (res.headersSent) {
    return next(error);
  }

  const errorStatus =
    error.status || error.statusCode;

  const status =
    Number.isInteger(errorStatus) &&
    errorStatus >= 400 &&
    errorStatus <= 599
      ? errorStatus
      : 500;

  // --------------------------------------------------
  // Server errors
  // --------------------------------------------------

  if (status >= 500) {
    console.error(error);

    return res.status(status).json({
      success: false,
      code: 'INTERNAL_ERROR',
      message: 'Internal server error',
    });
  }

  // --------------------------------------------------
  // Client / request errors
  // --------------------------------------------------

  return res.status(status).json({
    success: false,
    code:
      typeof error.code === 'string' &&
      error.code.trim()
        ? error.code
        : 'INVALID_REQUEST',
    message:
      typeof error.message === 'string' &&
      error.message.trim()
        ? error.message
        : 'Invalid request',
  });
}