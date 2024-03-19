'use strict';

const VerifyModes = Object.freeze({
    None      : 0,
    Optional  : 1,
    Required  : 2
});

Object.defineProperty( module.exports, "VerifyModes", {
    value: VerifyModes,
    enumerable: true,
    writable: false,
    configurable: false
});
