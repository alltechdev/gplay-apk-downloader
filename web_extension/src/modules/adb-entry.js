// Source for the bundled ADB module. esbuild rolls this + its yume-chan
// dependencies into src/vendor/adb-bundle.js (committed) so that the
// extension page can load WebUSB-based ADB without any CDN or runtime
// import-resolver.
//
// Public API attached to window.gplaydlAdb (module scope is otherwise
// unreachable from the inline page script):
//
//   await window.gplaydlAdb.connect()        // returns {model, android}
//   await window.gplaydlAdb.disconnect()
//   window.gplaydlAdb.connected              // boolean
//   await window.gplaydlAdb.shell(cmd)       // returns stdout string
//   await window.gplaydlAdb.installSplit(apks, onProgress)
//   window.gplaydlAdb.supported              // WebUSB feature detect

import { Adb, AdbDaemonTransport } from '@yume-chan/adb';
import { AdbDaemonWebUsbDeviceManager } from '@yume-chan/adb-daemon-webusb';
import AdbWebCredentialStore from '@yume-chan/adb-credential-web';

class AdbManager {
  constructor() {
    this.manager = AdbDaemonWebUsbDeviceManager.BROWSER;
    this.device = null;
    this.transport = null;
    this.adb = null;
    this.credentialStore = new AdbWebCredentialStore('GPlayADB');
  }

  get supported() { return !!this.manager; }
  get connected() { return !!this.adb; }

  async connect() {
    if (!this.manager) throw new Error('WebUSB not supported');
    await this.disconnect();

    const devices = await this.manager.getDevices();
    let target = null;
    const cached = localStorage.getItem('adbDevice');
    if (cached) {
      try {
        const info = JSON.parse(cached);
        target = devices.find((d) => d.serial === info.serial);
      } catch { /* corrupt cache */ }
    }
    if (!target && devices.length > 0) target = devices[0];
    if (target) {
      try { return await this._connectDevice(target); }
      catch { localStorage.removeItem('adbDevice'); target = null; }
    }
    target = await this.manager.requestDevice();
    if (!target) throw new Error('No device selected');
    return await this._connectDevice(target);
  }

  async _connectDevice(target) {
    localStorage.setItem('adbDevice', JSON.stringify({ serial: target.serial }));
    const connection = await target.connect();
    this.transport = await AdbDaemonTransport.authenticate({
      serial: target.serial,
      connection,
      credentialStore: this.credentialStore,
    });
    this.adb = new Adb(this.transport);
    this.device = target;
    return await this.getDeviceInfo();
  }

  async disconnect() {
    if (this.adb) { try { await this.adb.close(); } catch {} }
    this.adb = null;
    this.transport = null;
    this.device = null;
  }

  async getDeviceInfo() {
    const [model, android] = await Promise.all([
      this.shell('getprop ro.product.model'),
      this.shell('getprop ro.build.version.release'),
    ]);
    return { model: model.trim(), android: android.trim(), serial: this.device?.serial };
  }

  async shell(cmd) {
    return await this.adb.subprocess.noneProtocol.spawnWaitText(cmd);
  }

  async pushFile(blob, remotePath) {
    const sync = await this.adb.sync();
    try {
      await sync.write({ filename: remotePath, file: blob.stream(), permission: 0o644 });
    } finally {
      await sync.dispose();
    }
  }

  async installSplit(apks, onProgress) {
    const totalSize = apks.reduce((s, a) => s + a.size, 0);
    onProgress?.('create', 'Creating install session…');
    const createOut = await this.shell('pm install-create -S ' + totalSize);
    const match = createOut.match(/\[(\d+)\]/);
    if (!match) throw new Error('Failed to create session: ' + createOut.trim());
    const sessionId = match[1];
    try {
      for (let i = 0; i < apks.length; i++) {
        const apk = apks[i];
        const tmpPath = '/data/local/tmp/gplay_' + Date.now() + '_' + i + '.apk';
        onProgress?.('push', 'Pushing ' + apk.name + ' (' + (i + 1) + '/' + apks.length + ')…');
        await this.pushFile(apk.blob, tmpPath);
        onProgress?.('write', 'Writing ' + apk.name + ' to session…');
        const label = i === 0 ? 'base.apk' : 'split_' + i + '.apk';
        const writeOut = await this.shell('pm install-write -S ' + apk.size + ' ' + sessionId + ' ' + label + ' "' + tmpPath + '"');
        if (!writeOut.includes('Success')) throw new Error('install-write failed for ' + label + ': ' + writeOut.trim());
        await this.shell('rm -f "' + tmpPath + '"');
      }
      onProgress?.('commit', 'Committing install…');
      const commitOut = await this.shell('pm install-commit ' + sessionId);
      if (!commitOut.includes('Success')) throw new Error('Install failed: ' + commitOut.trim());
    } catch (e) {
      try { await this.shell('pm install-abandon ' + sessionId); } catch {}
      throw e;
    }
  }

  async listUserPackages() {
    const out = await this.shell('pm list packages -3');
    return out.split('\n').map((l) => l.replace('package:', '').trim()).filter(Boolean).sort();
  }
}

window.gplaydlAdb = new AdbManager();
