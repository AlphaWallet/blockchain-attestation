const path = require('path');

module.exports = {
    entry: './src/index.ts',
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                exclude: /node_modules/,
                use: [
                    { loader: 'ts-loader', options: { transpileOnly: true } }
                ]
            }
            ]
    },
    resolve: {
        extensions: [ '.tsx', '.ts', '.js' ],
        fallback:
            {
                "stream": require.resolve("stream-browserify") ,
                "assert": require.resolve("assert/")
            }

    },
    resolveLoader: {
        modules: ['node_modules'],
        extensions: ['.js', '.json'],
        mainFields: ['loader', 'main']
    },
    output: {
        filename: 'authenticator.js',
        path: path.resolve(__dirname, 'dist'),
    },
    // watch: true,
    watch: false,
    watchOptions: {
        aggregateTimeout: 200,
        poll: 1000,
        ignored: /node_modules/
    },
    optimization: {
        minimize: false
    }

};
