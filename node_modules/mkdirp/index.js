import fs from "fs";
import {dirname} from "path";

export const mkdirp = (dir, cb) =>
  fs.stat(dir, (err, stats) => {
    if (!err) stats.isDirectory()
      ? cb(null, dir)
      : cb(new Error(dir + ' is not a directory'))
    else if (err.code !== 'ENOENT') cb(err)
    else mkdirp(dirname(dir), err => err
        ? cb(err)
        : fs.mkdir(dir, cb))
  })

export const mkdirP = (dir) => new Promise((rs, rj) => mkdirp(dir, (e, d) => e ? rj(e) : rs(d)))
export default mkdirp
