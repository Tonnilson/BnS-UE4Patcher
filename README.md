# Blade and Soul UE4 Game Updater
An alternative method for installing and updating Blade & Soul for North America/Europe

![Main Image](https://i.imgur.com/CCf75hU.png)

## Description
We all know that NCLauncher2 pretty much sucks, there have been a lot of issues in the months to the launcher failing on certain files and halting the process. I originally wrote this code for Multi-Tool but with UE4 I separated the code and made a separate app just for installing and updating the game.

NCLauncher2 requires you to have at least 150GB free disk space to install the game otherwise you have to go through a bunch of steps to get it to work, not my UE4 Patcher. You will only need at the least 65GB of free disk space although it is recommended to have at least 80GB still.

The installing and patching process is faster thanks to parallel processing. At 1Gbps download speed with 6 threads it takes me roughly 35 minutes to download and install the game fresh.

## Getting Started

### Dependencies

* [.NET Framework 4.7.2](https://dotnet.microsoft.com/download/dotnet-framework/net472)

### Setting up
When first launching UE4 Patcher you will be prompted to select the game path, if you have already set the game path with NCLauncher2 you will use that same path (Example: F:\NCSOFT\BnS_UE4)

Afterwards you should be ready to go, you should tweak the updater threads to reflect your system. If you have a 6-core or higher processor you should use 4-6 updater threads. Please note that memory usage will be tied in with updater threads. Most will people want to have at least 4 updater threads, people with older machines will want to have 2.

## Features
* Parallel patching and downloading
* Lower space requirements for installing game
* Not an NC product so it actually works