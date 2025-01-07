import winston from 'winston';

const testTransport = new winston.transports.Console({
	format: winston.format.combine(
		winston.format.colorize(),
		winston.format.simple()
	)
});

const fileTransport = new winston.transports.File({
	filename: 'test.log',
	format: winston.format.json()
});

export const testLogger = winston.createLogger({
	level: 'debug',
	transports: [
		testTransport,
		fileTransport
	]
});