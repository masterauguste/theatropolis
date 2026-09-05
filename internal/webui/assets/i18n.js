"use strict";

(() => {
  const messages = window.theatropolisMessages;
  delete window.theatropolisMessages;

  const chinese = document.documentElement.lang.toLowerCase().startsWith("zh");
  window.theatropolisText = (english) => messages[english]?.[chinese ? "zh-CN" : "en"] || english;
  window.theatropolisLocale = chinese ? "zh-CN" : "en";
})();
