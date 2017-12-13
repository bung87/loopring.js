/*

  Copyright 2017 Loopring Project Ltd (Loopring Foundation).

  Licensed under the Apache License, Version 2.0 (the 'License');
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an 'AS IS' BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

const UglifyJSPlugin = require('uglifyjs-webpack-plugin');
const Path = require('path');
const defaultJSLoader = {
        test: /\.js$/,
        loader: 'babel-loader',
        exclude: /(node_modules)/,
        query: {
            presets : ['es2015', 'stage-0']
        }
    }
module.exports = {
    entry: './src/loopring.js',
    resolve: {
        modules: [
            'bower_components',
            'node_modules'
        ]
    },
    output: {
        path: Path.join(__dirname, '/dist'),
        library: 'loopring',
        libraryTarget: 'umd',
        filename: 'loopring.js'
    },
    // plugins: [
    //     new UglifyJSPlugin({
    //         exclude: /\/node_modules/,
    //         parallel: true,
    //         uglifyOptions: {
    //             beautify: true,
    //             ecma: 6,
    //             minimize: false,
    //             compress: false,
    //             comments: false
    //         }
    //     })
    // ],
    module:{
      loaders:[defaultJSLoader]
    },
    externals: {
        axios: 'axios',
        'bignumber.js': 'BigNumber',
        'bn.js': 'BN',
        lodash: '_'
    }
};
