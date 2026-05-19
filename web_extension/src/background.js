// background.js — service-worker entry. Each `sw/NN-*.js` file is a
// "module" in the importScripts sense: it loads into the SW's global
// scope, declares its functions/constants, and is consumed by later
// files in numeric order.
//
// Splitting this way (instead of `type: "module"`) avoids Chrome 144's
// flakiness with MV3 module service workers while keeping each concern
// in its own short file.
importScripts(
  'sw/00-config.js',
  'sw/10-utils.js',
  'sw/20-pb.js',
  'sw/30-storage.js',
  'sw/40-dnr.js',
  'sw/50-auth.js',
  'sw/60-play-api.js',
  'sw/70-downloads.js',
  'sw/80-search.js',
  'sw/90-action.js',
  'sw/99-rpc.js',
);
