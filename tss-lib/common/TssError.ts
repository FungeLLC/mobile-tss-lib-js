class TssError extends Error {
	constructor(message: any, ...params: any[]) {
		if(message instanceof Error) {
			message = message.message;
		} else if(typeof message !== 'string') {
			message = JSON.stringify(message);
		}
		if(params.length > 0) {
			message += ' (culprits: ' + params.map(p => p.toString()).join(',') + ')';
		}

		super(message);
		this.name = 'TssError';
	}
}

export { TssError };