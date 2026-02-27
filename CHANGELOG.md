# Changelog

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
