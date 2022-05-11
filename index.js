const net = require('net');
const TorControlError = require('./TorControlError');

class Tor {
    constructor({ host, port, password } = {}) {
        this.opts = {
            'host': host || 'localhost',
            'port': port || 9051,
            'password': password || '',
        }
    }

    async connect() {
        return new Promise((resolve, reject) => {
            this.connection = net.connect({ host: this.opts.host,  port: this.opts.port });

            this.connection
                .once('error', reject)
                .once('data', (data) => {
                    data = data.toString();
                    let ret = /([0-9]{1,3})\s(.*)\r\n/.exec(data);
                    if (ret !== null) {
                        const number = parseInt(ret[1]);
                        if (number === 250) {
                            return resolve({
                                type: number,
                                message: ret[2],
                                data: data,
                            });
                        }
                    }
                    
                    return reject(new TorControlError('Authentication failed.', data));
                });

            this.connection.write('AUTHENTICATE "' + this.opts.password + '"\r\n'); // Chapter 3.5
        });
    }
    
    async sendCommand(command) {
        if (this.connection === undefined) {
            throw new TorControlError('Need a socket connection (please call connect function)');
        }

        return new Promise((resolve, reject) => {
            this.connection
                .once('error', reject)
                .once('data', (data) => {
                    try {
                        data = data.toString();
                        let ret = /([0-9]{1,3})\s(.*)\r\n/.exec(data);
                        if (!ret) {
                            return reject(new TorControlError('Invalid response.', data));
                        }

                        return resolve({
                            type: parseInt(ret[1], 10),
                            message: ret[2],
                            data: data,
                        });
                    } catch (e) {
                        return reject(new TorControlError('Failed parsing data.', data));
                    }
                });

            this.connection.write(command + '\r\n');
        });
    }

    /*
    Reference by https://github.com/atd-schubert/node-tor-control/blob/master/index.js
                https://gitweb.torproject.org/torspec.git/tree/control-spec.txt
    */
    async quit() {
        return this.sendCommand('QUIT');
    }

    async setConf(request) { // Chapter 3.1
        return this.sendCommand('SETCONF ' + request);
    }

    async resetConf(request) { // Chapter 3.2
        return this.sendCommand('RESETCONF ' + request);
    }

    async getConf(request) { // Chapter 3.3
        return this.sendCommand('GETCONF ' + request);
    }

    async getEvents(request) { // Chapter 3.4
        return this.sendCommand('GETEVENTS ' + request);
    }

    async saveConf(request) { // Chapter 3.6
        return this.sendCommand('SAVECONF ' + request);
    }

    // Signals:
    async signal(signal) { // Chapter 3.7
        return this.sendCommand('SIGNAL ' + signal);
    }

    async signalReload() {
        return this.signal('RELOAD');
    }

    async signalHup() {
        return this.signal('HUP');
    }

    async signalShutdown() {
        return this.signal('SHUTDOWN');
    }

    async signalDump() {
        return this.signal('DUMP');
    }

    async signalUsr1() {
        return this.signal('USR1');
    }

    async signalDebug() {
        return this.signal('DEBUG');
    }

    async signalUsr2() {
        return this.signal('USR2');
    }

    async signalHalt() {
        return this.signal('HALT');
    }

    async signalTerm() {
        return this.signal('TERM');
    }

    async signalInt() {
        return this.signal('INT');
    }

    async signalNewnym() {
        return this.signal('NEWNYM');
    }

    async signalCleardnscache() {
        return this.signal('CLEARDNSCACHE');
    }

    async mapAddress(address) { // Chapter 3.8
        return this.sendCommand('MAPADDRESS ' + address);
    }

    async getInfo(request) { // Chapter 3.9
        if (!Array.prototype.isPrototypeOf(request)) {
            request = [request];
        }

        return this.sendCommand('GETINFO ' + request.join(' '));
    }

    extendCircuit(id, superspec, purpose) { // Chapter 3.10
        let str = 'EXTENDCIRCUIT ' + id;
        if (superspec) {
            str += ' ' + superspec;
        }
        if (purpose) {
            str += ' ' + purpose;
        }
        return this.sendCommand(str);
    }

    setCircuitPurpose(id, purpose) { // Chapter 3.11
        return this.sendCommand('SETCIRCUITPURPOSE ' + id + ' purpose=' + purpose);
    }
    setRouterPurpose(nicknameOrKey, purpose) { // Chapter 3.12
        return this.sendCommand('SETROUTERPURPOSE ' + nicknameOrKey + ' ' + purpose);
    }

    attachStream(streamId, circuitId, hop) { // Chapter 3.13
        let str = 'ATTACHSTREAM ' + streamId + ' ' + circuitId;

        if (hop) {
            str += ' ' + hop;
        }

        return this.sendCommand(str);
    }
}

Tor.TorControlError = TorControlError;

module.exports = Tor; 
