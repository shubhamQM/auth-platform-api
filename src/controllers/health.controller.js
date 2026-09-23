export function getHealth(req, res) {
  return res.status(200).json({
    success: true,
    message: 'Auth Platform API is running',
  });
}
