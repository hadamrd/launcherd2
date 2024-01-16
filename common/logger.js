import { format, createLogger, transports } from 'winston';
import jsonStringify from 'fast-safe-stringify';

const logLikeFormat = {
  transform(info) {
    const { timestamp, message } = info;
    const level = info[Symbol.for('level')];
    const args = info[Symbol.for('splat')]
    const strArgs = args ? args.map(jsonStringify).join(' ') : '';
    info[Symbol.for('message')] = `${timestamp} ${level}: ${message} ${strArgs}`;
    return info;
  }
};

const logger = createLogger({
  format: format.combine(
    format.timestamp(),
    logLikeFormat,
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'appLog.log' })
  ]
});

export default logger;