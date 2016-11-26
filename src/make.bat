@echo off
:: pdelaage commented : make.exe -f mingw.mak %1 %2 %3 %4 %5 %6 %7 %8 %9
:: on Windows, make is Borland make, but mingw.mak is NOW only compatible
:: with gnu make (due to various improvements I made, for compatibility between
:: linux and Windows host environments).
:: and echo OFF is the sign we are HERE on Windows, isn't it?...

mingw32-make.exe -f mingw.mak %1 %2 %3 %4 %5 %6 %7 %8 %9
