# Changelog

All changes to this project will be noted here.

## [3.4] - 2019-10-09 3:19 PM

- Fixed Typos in config.yaml for wpscan. Fixed enumWeb.CMS() . Write found source hostnames to log file.
- ToDo, Log all found hostnames to log file using logger instead of opening writing and closing files.
- Fixed really lame typo in recon.py in the FUNK_MAP.
- Fixed variable collision in vhostCrawl.py by renaming exception vars.
- Fixed all the :bug:'s :ant:

## [3.3] - 2019-10-09

### Added

- FTP Anonymous File Downloader. If anonymous ftp access is detected, O.G. Auto-Recon will attempt to download all available files from the ftp server.
- PHP Parameth parameter fuzzer option. For all found url's ending with the .php extension. Can be used with the --FUZZ option.
- More to come...
