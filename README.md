## LetterBomb web service implementation

This is the LetterBomb Wii System Menu 4.3 exploit implementation running on
https://letterbomb.andrewtech.net/. Requires Python 3.7+, Flask, and Flask-Limiter.

This does not include the HackMii Installer bundle. Those files would go
in `bundle/`.

### Differences from please.hackmii.com

 * ~~No captcha: I don't find it necessary and choose to implement rate limiting and anti-abuse controls in my server software instead~~ Looks like there's no more captcha (for now)
 * No Geo-IP detection: People *can* figure it out
 * Counter: Counts the number of unique LetterBombs performed based on the log file
 * Reverse proxy fixup: Application is reverse proxy aware, beware this may be a security issues if not using one!
 * ~~Currently working :)~~ Seems like they got it up again.


### License

GPL-2.0
