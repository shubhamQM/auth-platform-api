export function createCaptchaSecurity(config) {
  const secretKey = config?.captchaSecretKey;

  if (
    typeof secretKey !== 'string' ||
    !secretKey.trim()
  ) {
    throw new Error(
      'captchaSecretKey is required',
    );
  }

async function verifyCaptcha(token) {
  console.log(
    'CAPTCHA verification started',
    {
      tokenReceived:
        typeof token === 'string' &&
        token.trim().length > 0,
    },
  );

  if (
    typeof token !== 'string' ||
    !token.trim()
  ) {
    console.log(
      'CAPTCHA failed: token missing',
    );

    return false;
  }

  try {
    console.log(
      'Calling Google reCAPTCHA...',
    );

    const body = new URLSearchParams({
      secret: secretKey,
      response: token.trim(),
    });

    const response = await fetch(
      'https://www.google.com/recaptcha/api/siteverify',
      {
        method: 'POST',

        headers: {
          'Content-Type':
            'application/x-www-form-urlencoded',
        },

        body,
      },
    );

    console.log(
      'Google HTTP status:',
      response.status,
    );

    if (!response.ok) {
      console.log(
        'Google reCAPTCHA HTTP request failed',
      );

      return false;
    }

    const result =
      await response.json();

    console.log(
      'reCAPTCHA verification result:',
      {
        success: result?.success,
        hostname: result?.hostname,
        errorCodes:
          result?.['error-codes'] ?? [],
      },
    );

    return result?.success === true;
  } catch (error) {
  console.error(
    'reCAPTCHA verification error:',
    {
      message: error?.message,
      cause: error?.cause,
      code: error?.cause?.code,
    },
  );

  return false;
}
}

  return Object.freeze({
    verifyCaptcha,
  });
}