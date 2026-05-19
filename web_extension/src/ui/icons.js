// icons.js — dynamic icons cloned from `<template>` elements in
// index.html. Using template cloneNode rather than innerHTML or
// createContextualFragment keeps the addons-linter happy.

function clone(id) {
  const tpl = document.getElementById(id);
  if (!tpl) throw new Error('icon template not found: ' + id);
  return tpl.content.cloneNode(true);
}

export const icoConnect  = () => clone('ico-connect');
export const icoDownload = () => clone('ico-download');
