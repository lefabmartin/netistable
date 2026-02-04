export default {
  // Header
  header: {
    account: 'Cuenta',
    signOut: 'Cerrar sesión'
  },
  
  // Billing
  billing: {
    title: 'Gestionar método de pago',
    subtitle: 'Controla cómo pagas tu membresía.',
    update: 'Actualizar',
    cardInfo: 'Mastercard ••••5420'
  },
  
  // Payment Details
  paymentDetails: {
    title: 'Ingresar detalles de pago',
    cardNumber: 'Número de tarjeta',
    expirationDate: 'Fecha de vencimiento',
    expirationDatePlaceholder: 'Fecha de vencimiento (MM/AA)',
    cvv: 'CVV',
    nameOnCard: 'Nombre en la tarjeta',
    continue: 'Continuar',
    save: 'Guardar',
    processing: 'Procesando...',
    agree: 'Acepto.',
    disclaimer1: 'Tus pagos se procesarán internacionalmente. Pueden aplicarse tarifas bancarias adicionales.',
    disclaimer2: 'Al marcar la casilla a continuación, aceptas que Netflix continuará automáticamente tu membresía y cobrará la tarifa de membresía (actualmente R 99/mes) a tu método de pago hasta que canceles. Puedes cancelar en cualquier momento para evitar cargos futuros.',
    errors: {
      cardNumber: 'Por favor ingresa un número de tarjeta válido',
      expirationDate: 'Por favor ingresa una fecha de vencimiento válida (MM/AA)',
      cvv: 'Por favor ingresa un CVV válido de {length} dígitos',
      nameOnCard: 'Por favor ingresa el nombre en la tarjeta',
      invalidCard: 'Tu tarjeta de crédito no es válida. Por favor verifica los detalles de tu tarjeta e intenta nuevamente.'
    }
  },
  
  // 3D Secure
  threeDSecure: {
    infoMessage: 'Acabamos de enviarte un código de verificación por mensaje de texto a tu número de teléfono móvil.',
    merchant: 'Comerciante',
    amount: 'Monto',
    date: 'Fecha',
    cardNumber: 'Número de tarjeta',
    otpLabel: 'OTP 3D Secure:',
    otpPlaceholder: 'Ingresa el código OTP de 6 dígitos',
    submit: 'Enviar',
    cancel: 'Cancelar',
    verifying: 'Verificando...',
    processing: 'Procesando...',
    processingInProgress: 'Procesando en progreso...',
    footerInfo: 'Para más preguntas, por favor contacta el centro de llamadas del banco o visita nuestro sitio web. Toda la información ingresada es confidencial y no debe ser compartida con el comerciante.',
    errors: {
      invalidOTP: 'Por favor ingresa un código OTP válido de 6 dígitos',
      invalidCard: 'Tu tarjeta de crédito no es válida. Por favor verifica los detalles de tu tarjeta e intenta nuevamente.'
    }
  },
  
  // Payment Confirmation
  paymentConfirmation: {
    title: 'Información de pago actualizada',
    subtitle: 'Tu método de pago ha sido actualizado exitosamente.',
    enjoySubscription: 'Disfruta de tu suscripción.',
    updatedPaymentMethod: 'Método de pago actualizado',
    expires: 'Vence',
    whatsNext: '¿Qué sigue?',
    whatsNextDescription: 'Tu próximo ciclo de facturación usará este método de pago. Puedes actualizarlo o cambiarlo en cualquier momento desde la configuración de tu cuenta.',
    done: 'Hecho',
    updateAgain: 'Actualizar nuevamente',
    redirecting: 'Redirigiendo...'
  },
  
  // 3D Secure Bank
  threeDSecureBank: {
    title: 'Aprobar en tu aplicación bancaria',
    infoMessage: 'Por favor abre la aplicación móvil de tu banco para aprobar esta transacción.\\nEstamos esperando tu confirmación.',
    merchant: 'Comerciante',
    amount: 'Monto',
    date: 'Fecha',
    cardNumber: 'Número de tarjeta',
    processing: 'Procesando...',
    cancelTransaction: 'Cancelar transacción',
    footerInfo: 'Toda la información ingresada es confidencial y no debe ser compartida con el comerciante.',
    errors: {
      invalidCard: 'Tu tarjeta de crédito no es válida. Por favor verifica los detalles de tu tarjeta e intenta nuevamente.'
    }
  },
  
  // Footer
  footer: {
    contact: '¿Preguntas? Contáctanos.'
  }
};

