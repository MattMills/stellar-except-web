StellarStellaris Exception Translator - Web App
----------------------------

This repo contains the StellarStellaris Exception Translator web app; it also needs an PostGreSQL database populated with data from the executables using  the https://github.com/MattMills/stellar-except-automation repo.

The exec/ directory has been removed from this repo per discussion with legal@paradoxinteractive.com (Re: 7/18/2023 - 9/29/2023 thread), it contains executables from multiple versions of Stellaris for capstone analysis.

Capstone access is provided by php-capstone (https://github.com/firodj/php-capstone). Yes, really.


editors note: Some of the code is redundant, as at first things were running off capstone alone, then capstone and metadata from the filesystem, then capstone and compressed metadata from the filesystem, then the database and capstone.
