module.exports = {
	preset: "ts-jest",
	testEnvironment: "node",
	testMatch: ["**/__tests__/**/*.ts", "**/?(*.)+(spec|test).ts"],
	testPathIgnorePatterns: ["/node_modules/", "/dist/", "/go/"],
	verbose: true,
	collectCoverage: true,
	collectCoverageFrom: ["src/**/*.ts"],
	coverageDirectory: "coverage",
	coveragePathIgnorePatterns: ["/node_modules/", "/dist/", "/go/"],
	coverageReporters: ["json", "lcov", "text", "clover"],

	reporters: [
		"default",
		[
			"jest-console-reporter",
			{
				colorize: true,
				showPath: true,
			},
		],
	],
};