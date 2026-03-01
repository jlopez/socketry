# Changelog

## [0.2.1](https://github.com/jlopez/socketry/compare/socketry-v0.2.0...socketry-v0.2.1) (2026-03-01)


### Features

* **client:** add is_connected property to Subscription ([#27](https://github.com/jlopez/socketry/issues/27)) ([30d58bf](https://github.com/jlopez/socketry/commit/30d58bfcadac2e1fb8c2f299ad99de2dd9ccfdaa)), closes [#22](https://github.com/jlopez/socketry/issues/22)
* **client:** expose public user_id property ([#24](https://github.com/jlopez/socketry/issues/24)) ([9a7ef84](https://github.com/jlopez/socketry/commit/9a7ef846f7344133d08829be7ea6b12cd16679bd)), closes [#20](https://github.com/jlopez/socketry/issues/20)
* **client:** wrap MqttError; use KeyError consistently in device() SN lookup ([#26](https://github.com/jlopez/socketry/issues/26)) ([0963f6b](https://github.com/jlopez/socketry/commit/0963f6b9bfe516f2dc4115779cb631e513387f36)), closes [#21](https://github.com/jlopez/socketry/issues/21)


### Bug Fixes

* **ci:** use job-level path filtering for required checks compatibility ([#29](https://github.com/jlopez/socketry/issues/29)) ([d10ed85](https://github.com/jlopez/socketry/commit/d10ed85343f5b64d415976acba435bd412d73d46)), closes [#25](https://github.com/jlopez/socketry/issues/25)
* **ci:** use PAT for release-please to trigger CI on its PRs ([#31](https://github.com/jlopez/socketry/issues/31)) ([817b3b1](https://github.com/jlopez/socketry/commit/817b3b1646732d5bf746a3b1269afd5a5001dc27))

## [0.2.0](https://github.com/jlopez/socketry/compare/socketry-v0.1.1...socketry-v0.2.0) (2026-02-27)


### Features

* **client:** add Device class and shared MQTT connection ([#17](https://github.com/jlopez/socketry/issues/17)) ([332b162](https://github.com/jlopez/socketry/commit/332b162eccd2ef3a7ae323daaf8354aafd9b389f))
* **client:** implement token auto-refresh via re-authentication ([#18](https://github.com/jlopez/socketry/issues/18)) ([2720b5f](https://github.com/jlopez/socketry/commit/2720b5f379c67c2b6570d4b49d30dc0d645b9773)), closes [#9](https://github.com/jlopez/socketry/issues/9)
* **mqtt:** add subscription API and watch CLI for real-time updates ([#15](https://github.com/jlopez/socketry/issues/15)) ([4389952](https://github.com/jlopez/socketry/commit/43899521f87fe2ae8cb82a0cb849e2b9880cc926)), closes [#8](https://github.com/jlopez/socketry/issues/8)
* **mqtt:** replace paho-mqtt with aiomqtt for async MQTT support ([#13](https://github.com/jlopez/socketry/issues/13)) ([1d81bbe](https://github.com/jlopez/socketry/commit/1d81bbefb9f4023e81d23416a07cb174f3536318)), closes [#7](https://github.com/jlopez/socketry/issues/7)
* replace requests with aiohttp for async HTTP client ([#11](https://github.com/jlopez/socketry/issues/11)) ([faa4d71](https://github.com/jlopez/socketry/commit/faa4d71a8cf403440a6a895ba81107e1480fa054)), closes [#6](https://github.com/jlopez/socketry/issues/6)


### Bug Fixes

* **client:** persist refreshed token to disk and scope auto-save to from_saved() ([#19](https://github.com/jlopez/socketry/issues/19)) ([6fe470a](https://github.com/jlopez/socketry/commit/6fe470a9d0af935b12ebc5445390d0d5adf0c50e))


### Miscellaneous Chores

* release 0.2.0 ([fea5304](https://github.com/jlopez/socketry/commit/fea53043de7249efc1358aaeb6cb23b73b8112e0))

## [0.1.1](https://github.com/jlopez/socketry/compare/socketry-v0.1.0...socketry-v0.1.1) (2026-02-26)


### Bug Fixes

* add required HTTP headers for owned device listing ([#4](https://github.com/jlopez/socketry/issues/4)) ([1e66bda](https://github.com/jlopez/socketry/commit/1e66bdaf0e34546d1b8ee143eed3744950ea7035)), closes [#5](https://github.com/jlopez/socketry/issues/5)


### Documentation

* update README with PyPI install instructions ([#2](https://github.com/jlopez/socketry/issues/2)) ([86a494b](https://github.com/jlopez/socketry/commit/86a494b14eedb441dc977e4bcc2039277deb685a))

## 0.1.0 (2026-02-25)


### Features

* restructure as uv project with public API ([dc65617](https://github.com/jlopez/socketry/commit/dc656171e263fbc0a164e1ac2af0145b1fd9b9b4))
