const path = require('path');
const sass = require('sass');
const fs = require('fs');

const cssOutDir = '../cmd/server/static/css';

// Build styles
var result = sass.renderSync({
    file: 'src/main.scss',
    outFile: path.join(cssOutDir, 'main.css'),
    sourceMap: true,
});
fs.writeFileSync(
    path.join(cssOutDir, 'main.css'),
    result.css
);
fs.writeFileSync(
    path.join(cssOutDir, 'main.css.map'),
    result.map
);