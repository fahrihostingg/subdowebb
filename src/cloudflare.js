const axios = require('axios');

async function createDnsRecord({ zoneId, apiToken, name, type, content, proxied = false }) {
  try {
    const response = await axios.post(
      `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`,
      {
        type: type.toUpperCase(),
        name: name,
        content: content,
        ttl: 1, // Auto
        proxied: proxied
      },
      {
        headers: {
          'Authorization': `Bearer ${apiToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.data.success) {
      return { success: true, record: response.data.result };
    }
    return { success: false, error: response.data.errors[0]?.message || 'Gagal mencipta DNS di Cloudflare' };
  } catch (err) {
    return {
      success: false,
      error: err.response?.data?.errors?.[0]?.message || err.message
    };
  }
}

async function deleteDnsRecord({ zoneId, apiToken, recordId }) {
  try {
    const response = await axios.delete(
      `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${recordId}`,
      {
        headers: {
          'Authorization': `Bearer ${apiToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return { success: response.data.success };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

module.exports = { createDnsRecord, deleteDnsRecord };
