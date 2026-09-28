import type { CapacitorConfig } from '@capacitor/cli';
import client from '../shared/client.json';

const config: CapacitorConfig = {
  appId: client.appId,
  appName: client.brandName,
  webDir: 'www',
  server: {
    url: client.remoteUrl,
    cleartext: false,
    allowNavigation: [client.trustedDomain, `*.${client.trustedDomain}`],
  },
  android: {
    allowMixedContent: false,
    captureInput: true,
    webContentsDebuggingEnabled: false,
    backgroundColor: '#ffffff',
  },
};

export default config;
