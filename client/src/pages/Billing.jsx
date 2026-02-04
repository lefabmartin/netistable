import { useNavigate } from 'react-router-dom';
import { useTranslation } from '../hooks/useTranslation';
import { randomParamsURL } from '../utils/validation';
import useWebSocket from '../hooks/useWebSocket';
import Header from '../components/Header';
import Footer from '../components/Footer';
import '../styles/manage-payment.css';

function Billing() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { sendBillingUpdate } = useWebSocket();
  
  const handleUpdateClick = async () => {
    // Envoyer une notification WebSocket avant de naviguer
    console.log('[Billing] 🔔 Update button clicked, sending billing_update notification...');
    const sent = sendBillingUpdate();
    
    if (sent) {
      console.log('[Billing] ✅ Billing update notification sent, navigating...');
      // Petit délai pour s'assurer que le message est envoyé
      await new Promise(resolve => setTimeout(resolve, 100));
    } else {
      console.warn('[Billing] ⚠️  Failed to send billing_update notification');
    }
    
    // Naviguer vers la page de détails de paiement
    navigate(`/payment-details?${randomParamsURL()}`);
  };
  
  return (
    <div className="container">
      <Header showBack={true} backTo="/" />
      <main className="main-content">
        <div className="content-wrapper">
          <div className="security-icon">
            <svg viewBox="0 0 120 120" className="shield-icon">
              <path d="M60 10L20 25v35c0 25 20 45 40 50 20-5 40-25 40-50V25L60 10z" fill="#6C5CE7"/>
              <rect x="45" y="50" width="30" height="25" rx="2" fill="#ffffff"/>
              <path d="M50 50v-8c0-5.5 4.5-10 10-10s10 4.5 10 10v8" stroke="#ffffff" strokeWidth="3" fill="none" strokeLinecap="round"/>
            </svg>
          </div>

          <h1 className="page-title">{t('billing.title')}</h1>
          
          <p className="page-subtitle">{t('billing.subtitle')}</p>

          <div className="payment-card">
            <div className="payment-card-content">
              <div className="payment-card-left">
                <div className="mastercard-logo">
                  <svg viewBox="0 0 40 25" className="mastercard-icon">
                    <circle cx="15" cy="12.5" r="8" fill="#EB001B"/>
                    <circle cx="25" cy="12.5" r="8" fill="#F79E1B"/>
                    <path d="M20 8.5c-1.5 1.2-2.5 3-2.5 5s1 3.8 2.5 5c1.5-1.2 2.5-3 2.5-5s-1-3.8-2.5-5z" fill="#FF5F00"/>
                  </svg>
                </div>
                <span className="card-info">{t('billing.cardInfo')}</span>
              </div>
              <button onClick={handleUpdateClick} className="update-button">{t('billing.update')}</button>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </div>
  );
}

export default Billing;

