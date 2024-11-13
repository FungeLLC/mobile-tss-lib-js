class TssError extends Error {
	constructor(message: any) {
		if(message instanceof Error) {
			message = message.message;
		} else if(typeof message !== 'string') {
			message = JSON.stringify(message);
		}

		super(message);
		this.name = 'TssError';
	}
}

export { TssError };