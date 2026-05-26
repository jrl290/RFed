# fcm-bridge

`fcm-bridge` is the Android push relay for Retichat.

It exposes three Reticulum destinations:

- `rfed.notify` for wake packets emitted by rfed
- `fcm.register` for device token registration
- `fcm.unregister` for device token removal

## GitHub build output

The GitHub Actions workflow publishes:

- an artifact named `fcm_bridge-linux-x86_64`
- a container image tagged `ghcr.io/<owner>/fcm_bridge:latest`

## Runtime config

Mount a persistent `/data` volume and place these files there:

- `fcm_bridge.conf`
- `firebase-service-account.json`

Then run the published image:

```sh
docker run --rm -v /path/to/data:/data ghcr.io/<owner>/fcm_bridge:latest
```

On first start the bridge creates `/data/identity`, announces its destinations,
and logs the hashes you need for Android:

- `rfed.notify     hash: ...` -> `FCMRelayDestinationHash`
- `fcm.register    hash: ...` -> `FCMRegistrationDestinationHash`

Copy those two 32-character hex values into
`Retichat-android/app/src/main/assets/PushBridgeConfig.json` for your private
build.