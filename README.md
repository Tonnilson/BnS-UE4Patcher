# Blade and Soul UE4 Game Updater
An alternative method for installing and updating Blade & Soul for North America/Europe.

For the compiled binary please refer to the releases section https://github.com/Tonnilson/BnS-UE4Patcher/releases

![Main Image](https://i.imgur.com/CCf75hU.png)

## Description
We all know that NCLauncher2 pretty much sucks, there have been a lot of issues in the months to the launcher failing on certain files and halting the process. I originally wrote this code for Multi-Tool but with UE4 I separated the code and made a separate app just for installing and updating the game.

NCLauncher2 requires you to have at least 150GB free disk space to install the game otherwise you have to go through a bunch of steps to get it to work, not my UE4 Patcher. You will only need at the least 65GB of free disk space although it is recommended to have at least 80GB still.

The installing and patching process is faster thanks to parallel processing. At 1Gbps download speed with 6 threads it takes me roughly 35 minutes to download and install the game fresh.

## Getting Started

### Dependencies

* [.NET 6](https://dotnet.microsoft.com/en-us/download/dotnet/6.0)

### Setting up
When first launching UE4 Patcher you will be prompted to select the game path, If you already set the game path with NCLauncher you'll use that path (i.e C:\Program Files (x86)\NCSOFT\BnS_UE4)
If you have not already set the game path with NCLauncher you can just set your desired path, it's recommended to use the default naming scheme for each region if you intend to use NCLauncher (BnS_XXX) replace the XXX with one of the following below:

```
BNS_LIVE = NC Korea
BnS_UE4 = NCW (NA/EU)
BnS_TWBNSUE4 = NCT (Taiwan)
```

Afterwards you should be ready to go, you should tweak the updater threads to reflect your system. If you have a 6-core or higher processor you should use 4-6 updater threads. Please note that memory usage will be tied in with updater threads. Most will people want to have at least 4 updater threads, people with older machines and less than 16GB of RAM will want to use 2-3.

### Additional Notes / Information
This only downloads the games files, any prerequisites needed like C++ Redistributable will not be downloaded or installed but if you have any other modern games on your system this should not be a concern.

For people saying this is not safe, they're ignorant people. This downloads and updates the game the exact way that NCLauncher does the only difference is it manages resources (disk space) and is just faster due to being multi-threaded.

## Q&A
#### Why is this faster?
As stated above multiple times this utilizes paralell processing (multi-threading) to handle downloading and patching, it also uses .NET 6 which is significantly faster than .NET Framework 4.6 which is what NCLauncher uses

#### Is this really safe?
Again yes, it is safe. This retrieves the files the same way NCLauncher does and it applies patches the exact same way as NCLauncher.

#### Why does this require less space to install?
NCLauncher downloads files, merges files together and then decompresses those files then finally after all of that it moves or patches the file into where it needs to go, throughout that entire process it does not clean up after its self until it fully finishes thus leaving a bunch of junk left during the process.

UE4-Patcher downloads files, merges ones that need to be merged while removing the split parts then decompresses the file, after decompression the compressed file is removed and the decompressed file is moved or patched into where it needs to go.

## Features
* Parallel patching and downloading
* Lower space requirements for installing game
* Not an NC product so it actually works
