// SafeRoute: Backend Cloud Alert & Notification Dispatcher Service
// Dispatches emergency alerts exclusively via the authenticated /api/sos/alert server endpoint

import { normalizePhoneNumber } from './phoneUtils.js';
import { getOrRegisterDeviceToken } from './deviceTokenClient.js';

export class CloudAlertDispatcher {
  constructor() {
    this.apiEndpoint = '/api/sos/alert';
  }

  async dispatchEmergencyAlert({ sessionId, location, contacts, timestamp, liveTrackingUrl, userPhone }) {
    const normSystemNumber = normalizePhoneNumber(userPhone || '');

    const recipients = (contacts || []).map(c => {
      const normPhone = normalizePhoneNumber(c.phone || c.contactNumber || '');
      return {
        id: c.id || c.contactId,
        name: c.name || c.contactName || 'Emergency Contact',
        phone: normPhone,
        relation: c.relation || 'Contact',
        isPrimary: !!c.isPrimary
      };
    }).filter(c => c.phone);

    const payload = {
      sessionId,
      location: (location && typeof location.latitude === 'number' && typeof location.longitude === 'number') ? {
        latitude: location.latitude,
        longitude: location.longitude,
        accuracy: location.accuracy || null,
        timestamp: location.timestamp || null
      } : null,
      liveTrackingUrl: liveTrackingUrl || null,
      userPhone: normSystemNumber || null,
      timestamp: timestamp || new Date().toISOString(),
      contacts: recipients
    };

    try {
      const deviceToken = await getOrRegisterDeviceToken();

      const response = await fetch(this.apiEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(deviceToken ? { 'X-Device-Token': deviceToken } : {})
        },
        body: JSON.stringify({
          ...payload,
          deviceToken: deviceToken || undefined
        }),
        signal: AbortSignal.timeout(10000)
      });

      const data = await response.json().catch(() => ({}));

      if (response.ok && data.success) {
        return {
          success: true,
          status: 'SENT',
          deliveredCount: data.deliveredCount || 0,
          results: Array.isArray(data.results) ? data.results : recipients.map(r => ({ id: r.id, phone: r.phone, status: 'SENT' })),
          messageBody: data.messageBody
        };
      }

      // Honest failure handling when server returns 4xx, 5xx, or provider rejection
      return {
        success: false,
        status: 'FAILED',
        deliveredCount: data.deliveredCount || 0,
        error: data.error || `Server responded with status ${response.status}`,
        results: Array.isArray(data.results) ? data.results : recipients.map(r => ({
          id: r.id,
          phone: r.phone,
          status: 'FAILED',
          error: data.error || 'Server dispatch error'
        }))
      };
    } catch (netErr) {
      console.warn('Emergency alert network error:', netErr.message);
      return {
        success: false,
        status: 'FAILED',
        deliveredCount: 0,
        error: netErr.message || 'Network connection failed during SOS dispatch',
        results: recipients.map(r => ({
          id: r.id,
          phone: r.phone,
          status: 'FAILED',
          error: 'Network connection failed'
        }))
      };
    }
  }
}

export const cloudAlertDispatcher = new CloudAlertDispatcher();
