/* eslint-disable no-unused-vars */
const ZAAP_CONFIG = {}
ZAAP_CONFIG.ZAAP_GAME_ID = 102, ZAAP_CONFIG.ZAAP_EXECUTABLE = "zaap-start", ZAAP_CONFIG.ZAAP_TABS = {
    GAMES: "games",
    HOME: "home",
    VIDEO: "video",
    STREAM: "stream",
    SHOP: "shop",
    WEBTOON: "webtoon",
    COMPONENTS: "components"
}, ZAAP_CONFIG.ZAAP_SETTINGS_TABS = {
    BUG: "bug",
    NOTIFICATION: "notification",
    GENERAL: "general",
    HOME: "home",
    PERFORMANCE: "performance",
    TERMS: "terms",
    VERSION: "version",
    VIDEO: "video",
    MULTI_ACCOUNT: "multiAccount"
}, ZAAP_CONFIG.DEFAULT_ROUTE_FOR_TABS = {
    [ZAAP_CONFIG.ZAAP_TABS.GAMES]: "game", [ZAAP_CONFIG.ZAAP_TABS.HOME]: "home", [ZAAP_CONFIG.ZAAP_TABS.VIDEO]: "video", [ZAAP_CONFIG.ZAAP_TABS.STREAM]: "stream", [ZAAP_CONFIG.ZAAP_TABS.WEBTOON]: "webtoon", [ZAAP_CONFIG.ZAAP_TABS.COMPONENTS]: "components", [ZAAP_CONFIG.ZAAP_TABS.SHOP]: "shop"
}, ZAAP_CONFIG.ZAAP_INVITE_GROUPS = {
    SENT: "sent",
    PENDING: "pending",
    BLOCKED: "blocked"
}, ZAAP_CONFIG.ZAAP_CHAT_TABS = {
    CHANNELS: "channels",
    FRIENDS: "friends",
    INVITES: "invites"
}, ZAAP_CONFIG.ZAAP_ACCOUNT_TABS = {
    NEWSLETTER: "newsletter"
}, ZAAP_CONFIG.ZAAP_USER_STATUS = {
    ONLINE: "online",
    AWAY: "away",
    BUSY: "busy",
    OFFLINE: "offline"
}, ZAAP_CONFIG.ZAAP_GAME_PLAY_MODE = {
    QUEUE: "queue",
    ALL: "all",
    OFFLINE: "offline"
}, ZAAP_CONFIG.ZAAP_PERFOMANCE_PRESELECT = [{
    name: "lp",
    label: "low",
    iconName: "selectConfigLP",
    options: {
        ENABLE_ANIMATIONS: !0,
        ENABLE_VIDEO: !1,
        IMAGE_QUALITY: "lq",
        KEEP_AT_GAME_LAUNCH: !1
    }
}, {
    name: "mp",
    label: "medium",
    default: !0,
    iconName: "selectConfigMP",
    options: {
        ENABLE_ANIMATIONS: !0,
        ENABLE_VIDEO: !0,
        IMAGE_QUALITY: "mq",
        KEEP_AT_GAME_LAUNCH: !0
    }
}, {
    name: "hp",
    label: "high",
    iconName: "selectConfigHP",
    options: {
        ENABLE_ANIMATIONS: !0,
        ENABLE_VIDEO: !0,
        IMAGE_QUALITY: "hq",
        KEEP_AT_GAME_LAUNCH: !0
    }
}, {
    name: "cp",
    label: "custom",
    disabled: !0,
    options: {}
}], ZAAP_CONFIG.ZAAP_CYTRUS_CONFIG = {
    SPEED: {
        MIN: 262144,
        MAX: 134217728
    },
    RAM: {
        MIN: 67108864,
        MAX: 536870912
    }
}, ZAAP_CONFIG.TIMEOUT_OPTIONS = {
    minTimeout: 5e3,
    maxTimeout: 2e4,
    retries: 3,
    randomize: !0
}, ZAAP_CONFIG.FLAP_TYPES = {
    CHAT: "chat",
    ACCOUNT: "account",
    MAIN_SETTINGS: "main_settings",
    GAME_SETTINGS: "game_settings",
    FAVORITE_GAMES: "favorite_games"
}, ZAAP_CONFIG.FLAP_SIDES = {
    LEFT: "left",
    RIGHT: "right"
}, ZAAP_CONFIG.LANGUAGE_LABELS = {
    DE: "Deutsch",
    ES: "Español",
    EN: "English",
    FR: "Français",
    IT: "Italiano",
    PT: "Português"
}, ZAAP_CONFIG.TWITCH_LANGS = {
    fr: "fr_FR",
    en: "en_GB",
    es: "es_ES",
    pt: "pt_PT"
}, ZAAP_CONFIG.STREAMS = {
    NOTIFICATION_STREAMERS_LIST: ["ankamalive"]
}, ZAAP_CONFIG.GO_SHOP_TO = {
    ogrines: "shop-ogrines",
    dofus: "shop-dofus",
    retro: "shop-dofus-retro",
    wakfu: "shop-wakfu",
    krosmaga: "shop-krosmaga",
    webtoonToken: "shop-packs"
}, ZAAP_CONFIG.SHOP_ERROR_KEYS = {
    INTERNAL_SERVER_ERROR: "internal_server_error",
    INVALID_SHOP_API_KEY: "invalid_shop_api_key"
}, ZAAP_CONFIG.SHOP_HAAPI_KEYS = {
    SHOP_KEY: "ZAAP",
    PAYMENT_MODE: "OK"
}, ZAAP_CONFIG.CHAT = {
    GAME_ID: 99,
    MAX_NB_PSEUDO_IN_MSG: 3,
    TYPING_TIMEOUT: 1e4,
    ACTIVITIES: {
        IN_LAUNCHER: "IN_LAUNCHER",
        READING_NEWS: "READING_NEWS",
        WATCHING_STREAM: "WATCHING_STREAM",
        WATCHING_VIDEO: "WATCHING_VIDEO"
    }
}, ZAAP_CONFIG.WEBTOONS = {
    DEBOUNCE_DURATION: 500,
    PLAYER_IMAGE_ZOOM: .55
}, ZAAP_CONFIG.AUTH_NB_ERROR_BEFORE_WARNING = 10, ZAAP_CONFIG.PIP_WINDOW = {
    MIN_WIDTH: 300,
    MIN_HEIGHT: 200,
    DEFAULT_WIDTH: 600,
    DEFAULT_HEIGHT: 400
}, ZAAP_CONFIG.ACCOUNT_DETAILS_OPTIONS = {
    NONE: {
        label: "home.none"
    },
    ABODOFUS: {
        gameId: 1,
        label: "home.aboDofus"
    },
    BOOSTERWAKFU: {
        gameId: 3,
        label: "home.boosterWakfu"
    },
    PLAYTIME: {
        label: "home.playedTime"
    }
}, ZAAP_CONFIG.UNIVERSE_SERVICE_NAMES = {
    GAMES: "games",
    VIDEO: "video",
    TWITCH: "twitch",
    WEBTOON: "webtoon",
    SHOP: "shop"
}, ZAAP_CONFIG.UPDATE_TYPES = {
    INSTALL: "INSTALL",
    UPGRADE: "UPGRADE",
    REPAIR: "REPAIR",
    UNINSTALL: "UNINSTALL"
}, ZAAP_CONFIG.TUTORIAL_UNIVERSE_KEY = "universe", ZAAP_CONFIG.USER_ACCOUNT_LOCKED = {
    MAILNOVALID: "2"
}
const ZAAP_ACTIONS = {
    AUTH_ACCOUNT_ACTIVATE: "account.activate",
    AUTH_GET: "auth.get",
    AUTH_LOGIN: "auth.login",
    AUTH_LOGOUT: "auth.logout",
    AUTH_ADD_ACCOUNT: "auth.addAccount",
    AUTH_REMOVE_ACCOUNT: "auth.removeAccount",
    AUTH_PROVIDER_CREATE_GHOST: "auth.provider.createGhost",
    AUTH_PROVIDER_LINK: "auth.provider.link",
    AUTH_PROVIDER_LOGIN: "auth.provider.login",
    AUTH_PROVIDER_NEED_LINK: "auth.provider.needLink",
    AUTH_PROVIDER_WINDOW_OPEN: "auth.provider.windowOpen",
    AUTH_PROVIDER_UPDATE_ACCESS_TOKEN: "auth.provider.updateAccessToken",
    AUTH_UPDATED: "auth.updated",
    AUTH_EXPIRED_SESSION: "auth.expired.session",
    AUTH_CREATE_TOKEN: "auth.createToken",
    SET_MAIN_USER: "set.main.user",
    VALIDATE_CODE: "validate.code",
    RESEND_CODE: "resend.code",
    SHIELD_BLOCK: "shield.block",
    STAY_LOGGED_IN: "stay.logged.in",
    OPEN_STAY_LOGGED_IN_POPUP: "open.stay.logged.in.popup",
    OPEN_TRAY_AT_CLOSE_POPUP: "open.tray.at.close.popup",
    SIGNUP_WEBVIEW_RESPONSE: "signup.webview.response",
    SIGNUP_CLOSE_WEBVIEW: "signup.close.webview",
    CHAT_ACCEPT_INVITE_SEND: "chat.accept.invite.send",
    CHAT_ADD_MEMBER_TO_GROUP_CHANNEL_SEND: "chat.add.member.to.group.channel.send",
    CHAT_BLOCK_CONTACT_SEND: "chat.block.contact.send",
    CHAT_BLOCK_CONTACT_SEND_ERROR: "chat.block.contact.send.error",
    CHAT_BLOCKED_LIST_SEND: "chat.blocked.list.send",
    CHAT_BLOCKED_LIST_RECEIVED: "chat.blocked.list.received",
    CHAT_CANCEL_INVITE_SEND: "chat.cancel.invite.send",
    CHAT_CHANNEL_MESSAGES_LIST_SEND: "chat.channel.messages.list.send",
    CHAT_CHANNEL_LIST_RECEIVED: "chat.channel.list.received",
    CHAT_CHANNEL_LIST_SEND: "chat.channel.list.send",
    CHAT_CONNECTED: "chat.connected",
    CHAT_CONNECTION_ERROR_SEND: "chat.connection.error.send",
    CHAT_CREATE_BLOCKED_CONTACT_RECEIVED: "chat.create.blocked.contact.received",
    CHAT_CREATE_GROUP_CHANNEL_SEND: "chat.create.group.channel.send",
    CHAT_CREATE_GROUP_ERROR: "chat.create.group.error",
    CHAT_CREATE_GROUP_SEND: "chat.create.group.send",
    CHAT_CREATE_GROUP_RECEIVED: "chat.create.group.received",
    CHAT_CREATE_INVITE_ERROR: "chat.create.invite.error",
    CHAT_CREATE_INVITE_RECEIVED: "chat.create.invite.received",
    CHAT_CREATE_MESSAGE_RECEIVED: "chat.create.message.received",
    CHAT_CREATE_ACTIVITY: "chat.create.activity",
    CHAT_DELETE_BLOCKED_CONTACT_RECEIVED: "chat.delete.blocked.contact.received",
    CHAT_DELETE_CHANNEL_RECEIVED: "chat.delete.channel.received",
    CHAT_DELETE_CHANNEL_SEND: "chat.delete.channel.send",
    CHAT_DELETE_FRIEND_ERROR: "chat.delete.friend.error",
    CHAT_DELETE_FRIEND_RECEIVED: "chat.delete.friend.received",
    CHAT_DELETE_FRIEND_SEND: "chat.delete.friend.send",
    CHAT_DELETE_GROUP_ERROR: "chat.delete.group.error",
    CHAT_DELETE_GROUP_RECEIVED: "chat.delete.group.received",
    CHAT_DELETE_GROUP_SEND: "chat.delete.group.send",
    CHAT_DELETE_MEMBER_FROM_GROUP_CHANNEL_SEND: "chat.delete.member.from.group.channel.send",
    CHAT_DELETE_INVITE_ERROR: "chat.delete.invite.error",
    CHAT_DELETE_INVITE_RECEIVED: "chat.delete.invite.received",
    CHAT_DISCONNECTED: "chat.disconnected",
    CHAT_ENDPOINT_RECEIVE: "chat.endpoint.receive",
    CHAT_FOCUS_ACTIVE_CHANNEL: "chat.focus.active.channel",
    CHAT_FOCUS_CHAT_INVITES_TAB: "chat.focus.chat.invites.tab",
    CHAT_FRIEND_ADD_NOTE: "chat.friend.add.note",
    CHAT_FRIEND_GROUP_LIST_RECEIVED: "chat.friend.group.list.received",
    CHAT_FRIEND_LIST_ERROR: "chat.friend.list.error",
    CHAT_FRIEND_LIST_RECEIVED: "chat.friend.list.received",
    CHAT_FRIEND_LIST_SEND: "chat.friend.list.send",
    CHAT_GROUP_CHANNEL_LIST_SEND: "chat.group.channel.list.send",
    CHAT_GROUP_CHANNEL_MEMBERS_LIST_SEND: "chat.group.channel.members.list.send",
    CHAT_GROUP_CHANNEL_MESSAGE_SEND: "chat.group.channel.message.send",
    CHAT_INVITE_LIST_SEND: "chat.invite.list.send",
    CHAT_INVITE_LIST_RECEIVED: "chat.invite.list.received",
    CHAT_INVITE_SEND: "chat.invite.send",
    CHAT_MESSAGE_SEND: "chat.message.send",
    CHAT_MESSAGES_LIST_SEND: "chat.messages.list.send",
    CHAT_MESSAGES_LIST_RECEIVED: "chat.messages.list.received",
    CHAT_NOTIFICATION_ACCEPT_INVITE: "chat.notification.accept.invite",
    CHAT_NOTIFICATION_FRIEND_PRESENCE: "chat.notification.friend.presence",
    CHAT_NOTIFICATION_NEW_INVITE: "chat.notification.newInvite",
    CHAT_NOTIFICATION_NEW_MESSAGE: "chat.notification.newMessage",
    CHAT_NOTIFICATION_REJECT_INVITE: "chat.notification.reject.invite",
    CHAT_NOTIFICATION_REPLY: "chat.notification.reply",
    CHAT_PROCESS_READY: "chat.process.ready",
    CHAT_RECONNECTION_SEND: "chat.reconnection.send",
    CHAT_REJECT_INVITE_SEND: "chat.reject.invite.send",
    CHAT_UNLOCK_CONTACT_SEND: "chat.unlock.contact.send",
    CHAT_UNLOCK_CONTACT_SEND_ERROR: "chat.unlock.contact.send.error",
    CHAT_UPDATE_GROUP_CHANNEL_SEND: "chat.udpate.group.channel.send",
    CHAT_UPDATE_FRIEND_ERROR: "chat.update.friend.error",
    CHAT_UPDATE_FRIEND_GROUP_SEND: "chat.update.friend.group.send",
    CHAT_UPDATE_FRIEND_RECEIVED: "chat.update.friend.received",
    CHAT_UPDATE_PRESENCE_RECEIVED: "chat.update.presence.received",
    CHAT_UPDATE_STATUS_RECEIVED: "chat.update.status.received",
    CHAT_UPDATE_STATUS_SEND: "chat.update.status.send",
    CONNECTIVITY_UPDATED: "zaap.connectivity.updated",
    CONNECTIVITY_GET: "connectivity.get",
    FACEBOOK_GET_ACCESS_TOKEN_URL: "facebook.getAccessTokenUrl",
    FACEBOOK_GET_EMAIL: "facebook.getEmail",
    FACEBOOK_GET_LOGOUT_URL: "facebook.getLogoutUrl",
    FACEBOOK_OPEN_GET_ACCESS_TOKEN_WINDOW: "facebook.open.get.access.token.window",
    FACEBOOK_CLOSE_GET_ACCESS_TOKEN_WINDOW: "facebook.close.get.access.token.window",
    FACEBOOK_LOGOUT_WINDOW: "facebook.logout.window",
    FACEBOOK_LOGOUT: "facebook.logout",
    FACEBOOK_SET_ACCESS_TOKEN: "facebook.set.access.token",
    OVERLAY_GET: "overlay.get",
    OVERLAY_CLOSE: "overlay.close",
    OVERLAY_OPEN: "overlay.open",
    OVERLAY_CONFIRM_PAYMENT: "overlay.confirm.payment",
    RELEASE_ERROR: "release.error",
    RELEASE_GET_INSTALL_INFORMATION: "release.getInstallInformation",
    RELEASE_GET_FOLDER_SIZE: "release.getFolderSize",
    RELEASE_GET_FOLDER_SIZE_RESULT: "release.getFolderSizeResult",
    RELEASE_GET_LICENSES: "release.getLicences",
    RELEASE_SETTINGS_UPDATE: "release.gameSettings.update",
    RELEASE_INSTALL: "release.install",
    RELEASE_INSTALL_ERROR: "release.install.error",
    RELEASE_INSTALL_STARTED: "release.install.started",
    RELEASE_MOVE: "release.move",
    RELEASE_MOVE_ERROR: "release.move.error",
    RELEASE_MOVE_SUCCESS: "release.move.success",
    RELEASE_NEWS_CLICK: "release.news.click",
    RELEASE_REPAIR: "release.repair",
    RELEASE_CREATE_SHORTCUT: "release.create.shortcut",
    RELEASE_BAD_SHORTCUT: "release.bad.shortcut",
    RELEASE_START: "release.start",
    RELEASE_START_WITH_ACCOUNT: "release.start.with.account",
    RELEASE_UNINSTALL: "release.uninstall",
    RELEASE_UNINSTALL_DONE: "release.uninstall.done",
    RELEASE_UNINSTALL_ERROR: "release.uninstall.error",
    RELEASE_UPDATE: "release.update",
    RELEASE_UPDATE_CANCEL: "release.update.cancel",
    RELEASE_UPDATE_COMPLETE: "release.update.complete",
    RELEASE_UPDATE_PAUSE: "release.update.pause",
    RELEASE_UPDATE_RESUME: "release.update.resume",
    RELEASE_UPDATE_UPDATED: "release.update.updated",
    RELEASE_UPDATED: "release.updated",
    RELEASE_WAS_LAUNCHED: "release.wasLaunched",
    RELEASE_ACTIF_CHANGED: "release.actif.changed",
    REFRESH_USER_GAMELIST: "refresh.user.gamelist",
    REFRESH_ALL_USER_GAMELIST: "refresh.all.user.gamelist",
    RELEASE_OPEN_LOGDIR: "release.open.logdir",
    RELEASE_OPEN_LOCATION: "release.open.location",
    GET_ALL_NEWS: "get.all.news",
    GET_SINGLE_NEWS: "get.single.news",
    GET_CAROUSEL: "get.carousel",
    CHANGELOG_GET: "changelog.get",
    CHANGELOGS_GET: "changelogs.get",
    GET_OGRINS: "get.ogrins",
    GET_PURCHASE_URL: "get.purchase.url",
    GET_ARTICLE_BY_ID: "get.articleById",
    GET_ARTICLE_BY_ID_ERROR: "get.articleById.error",
    PURCHASE_WITH_OGRINS: "purchase.with.ogrins",
    PURCHASE_WITH_OGRINS_PROCESSED: "purchase.with.ogrins.processed",
    REFRESH_SHOP: "refresh.shop",
    REFRESH_SHOP_ERROR: "refresh.shop.error",
    REFRESH_SHOP_CATEGORY: "refresh.shop.category",
    REFRESHED_SHOP_SUBCATEGORY: "refreshed.shop.subcategory",
    REFRESHED_SHOP_CATEGORY: "refreshed.shop.category",
    USER_EMAIL_INVALID: "user.email.invalid",
    USER_GET: "user.get",
    USER_FULLNAME_MISSING: "user.fullname.missing",
    USER_NICKNAME_CHANGED: "user.nickname.changed",
    USER_NICKNAME_ERROR: "user.nickname.error",
    USER_NICKNAME_MISSING: "user.nickname.missing",
    USER_SET_NICKNAME: "user.set.nickname",
    USER_SET_FULLNAME: "user.set.fullname",
    USER_SET_MAIL: "user.set.mail",
    REFRESH_USER_INFO: "refresh.user.info",
    USER_SEND_VALIDATION_MAIL: "user.send.validation.mail",
    USER_MAIL_UPDATED: "user.mail.updated",
    USER_MAIL_UPDATED_ERROR: "user.mail.updated.error",
    USER_VALIDATION_MAIL_SENT: "user.validation.mail.sent",
    USER_UPDATED: "user.updated",
    USER_SET_NOTE: "user.set.note",
    NEWSLETTER_GET: "newsletter.get",
    NEWSLETTER_SUBSCRIBE: "newsletter.subscribe",
    USER_ACTIVITIES_CHANGE: "user.activities.change",
    USER_ACTIVITIES_GET: "user.activities.get",
    TOWER_SET_ACCESS_TOKEN: "tower.set.access.token",
    TOWER_SET_ACCESS_TOKEN_DONE: "tower.set.access.token.done",
    TOWER_GET_SERIES_LIST: "tower.get.series.list",
    TOWER_GET_SERIES_NEW_EPISODES_LIST: "tower.get.series.new.episodes.list",
    TOWER_GET_SERIES: "tower.get.series",
    TOWER_FOLLOW_SERIES: "tower.follow.series",
    TOWER_GET_EPISODE: "tower.get.episode",
    TOWER_GET_EPISODES_FROM_SERIES: "tower.get.episodes.from.series",
    TOWER_GET_EPISODES_FROM_FOLLOWED_SERIES: "tower.get.episodes.from.followed.series",
    TOWER_EPISODE_TOGGLE_LIKE: "tower.episode.toggle.like",
    TOWER_EPISODE_TOGGLE_WISHLIST: "tower.episode.toggle.wishlist",
    TOWER_EPISODE_REMOVE_FROM_HISTORY: "tower.episode.remove.from.history",
    TOWER_EPISODE_UNLOCK_EPISODES: "tower.episode.unlock.episodes",
    TOWER_EPISODE_GET_COMMENTS: "tower.episode.get.comments",
    TOWER_EPISODE_GET_CHILD_COMMENTS: "tower.episode.get.child.comments",
    TOWER_EPISODE_CREATE_COMMENT: "tower.episode.create.comment",
    TOWER_EPISODE_UPDATE_COMMENT: "tower.episode.update.comment",
    TOWER_EPISODE_DELETE_COMMENT: "tower.episode.delete.comment",
    TOWER_EPISODE_REPLY_TO_COMMENT: "tower.episode.reply.to.comment",
    TOWER_EPISODE_REPORT_COMMENT: "tower.episode.report.comment",
    TOWER_EPISODE_REACT_COMMENT: "tower.episode.react.comment",
    TOWER_USER_GET_FOLLOWED_SERIES: "tower.user.get.followed.series",
    TOWER_USER_GET_LIKED_EPISODES: "tower.user.get.liked.episodes",
    TOWER_USER_GET_UNLOCKED_EPISODES: "tower.user.get.unlocked.episodes",
    TOWER_USER_GET_READING_HISTORY: "tower.user.get.reading.history",
    TOWER_USER_GET_WISHLIST: "tower.user.get.wishlist",
    TOWER_USER_GET_RECOMMENDATIONS: "tower.user.get.recommendations",
    TOWER_SESSION_GET_SESSION_ID: "tower.session.get.session.id",
    TOWER_SESSION_GET_READING_SESSION_ID: "tower.session.get.reading.session.id",
    TOWER_SESSION_ADD_READING_DETAILS: "tower.session.add.reading.details",
    TOWER_STOCK_GET_WEBTOON_TOKEN: "tower.stock.get.webtoon.token",
    VIDEO_REFRESH_VOD_TOKEN: "video.refresh.vod.token",
    VIDEO_GET_SERIES_LIST: "video.getSeriesList",
    VIDEO_GET_SERIES_LIST_WITH_HISTORY: "video.getSeriesListWithHistory",
    VIDEO_GET_TERMS: "video.getTerms",
    VIDEO_GET_SUBTITLE: "video.getSubtitle",
    VIDEO_GET_VIDEO_URL: "video.getVideoUrl",
    VIDEO_GET_HISTORY: "video.getHistory",
    VIDEO_GET_SEASON: "video.get.season",
    VIDEO_GET_SERIES: "video.get.series",
    VIDEO_GET_VIDEO: "video.get.video",
    VIDEO_LIST_SERIES: "video.list.series",
    VIDEO_LIST_SERIES_SEASONS: "video.list.series.seasons",
    VIDEO_LIST_SERIES_VIDEOS: "video.list.series.videos",
    VIDEO_LIST_SEASON_VIDEOS: "video.list.season.videos",
    VIDEO_DELETE_HISTORY: "video.deleteHistory",
    VIDEO_READ_VIDEO: "video.markVideoAsRead",
    VIDEO_UPDATE_HISTORY: "video.updateHistory",
    WINDOW_FULLSCREEN: "window.fullscreen",
    WINDOW_HIDE: "window.hide",
    WINDOW_IS_FOCUSED: "window.isFocused",
    WINDOW_IS_FULLSCREEN: "window.isFullscreen",
    WINDOW_IS_MAXIMIZED: "window.isMaximized",
    WINDOW_SET_SIZE: "window.set.size",
    WINDOW_MAXIMIZE: "window.maximize",
    WINDOW_MINIMIZE: "window.minimize",
    WINDOW_UNMAXIMIZE: "window.unmaximize",
    WINDOW_SET_TITLE: "window.set.title",
    ZAAP_CLEAR_CACHE: "zaap.clear.cache",
    ZAAP_AUTO_UPDATER_INSTALL: "zaap.autoUpdater.install",
    ZAAP_AUTO_UPDATER_PROGRESS: "zaap.autoUpdater.progress",
    ZAAP_AUTO_UPDATER_READY: "zaap.autoUpdater.ready",
    ZAAP_AUTO_UPDATER_FORCE_UPDATE: "zaap.autoUpdater.force.asking",
    ZAAP_GET_DEFAULT_LANGUAGE: "zaap.getDefaultLanguage",
    ZAAP_GET_SUPPORTED_LANGUAGES: "zaap.getSupportedLanguages",
    ZAAP_GET_VERSION: "zaap.getVersion",
    ZAAP_LANGUAGE_UPDATED: "zaap.language.updated",
    ZAAP_QUIT: "zaap.quit",
    ZAAP_RELAUNCH: "zaap.relaunch",
    ZAAP_SETTINGS_GET: "zaap.settings.get",
    ZAAP_SETTINGS_GET_VALUE: "zaap.settings.getValue",
    ZAAP_SETTINGS_OPEN: "zaap.settings.open",
    ZAAP_SETTINGS_SET: "zaap.settings.set",
    ZAAP_SETTINGS_UPDATED: "zaap.settings.updated",
    ZAAP_OPEN_DIALOG: "zaap.open.dialog",
    ZAAP_GET_PATH: "zaap.get.path",
    ZAAP_CALCUL_DL_SPEED: "zaap.calcul.dl.speed",
    UNINSTALLER_FINISH: "uninstaller.finish",
    UNINSTALLER_CANCEL: "uninstaller.cancel",
    UNINSTALLER_MINIMIZE: "uninstaller.minimize",
    UNINSTALLER_GAMES_START: "uninstaller.games.start",
    UNINSTALLER_GAMES_ERROR: "uninstaller.games.error",
    UNINSTALLER_GAMES_PROGRESS: "uninstaller.games.progress",
    TWITCH_GET_STREAMER_LIST: "twitch.get.streamer.list",
    TWITCH_GET_ANKAMALIVE_PREVIOUS_VIDEOS: "twitch.get.ankamalive.previous.videos",
    TWITCH_GET_CURRENT_STREAMS: "twitch.get.current.streams",
    TWITCH_KPI_LIVE_STREAMS: "twitch.kpi.live.streams",
    TWITCH_KPI_REBROADCAST_STREAMS: "twitch.kpi.rebroadcast.streams",
    TWITCH_LOGIN: "twitch.login",
    TWITCH_LOGOUT: "twitch.logout",
    TWITCH_REFRESH_USER_INFO: "twitch.refresh.user.info",
    TWITCH_REFRESH_VIEW: "twitch.refresh.view",
    TWITCH_SET_USER_AUTH_STATUS: "twitch.set.user.auth.status",
    TWITCH_SET_USER_DISPLAY_NAME: "twitch.set.user.display.name",
    TWITCH_GET_DROPS: "twitch.get.drops",
    TWITCH_CONSUME_DROP: "twitch.consume.drop",
    EMOJI_PANEL_IS_SUPPORTED: "emoji_panel.is.supported",
    EMOJI_PANEL_OPEN: "emoji_panel.open",
    PIP_OPEN: "pip.open",
    PIP_CLOSE: "pip.close",
    PIP_ASK_CLOSE: "pip.ask.close",
    PIP_CLOSED: "pip.closed",
    PIP_SET_INFORMATION: "pip.set.information",
    UNIVERSE_GET_AVAILABLE_UNIVERSES: "universe.get.available",
    UNIVERSE_GET_SELECTED_UNIVERSE: "universe.get.selected",
    UNIVERSE_GET_UNIVERSE: "universe.get.universe",
    UNIVERSE_SET_SELECTED: "universe.set.selected",
    UNIVERSE_SELECT: "universe.select",
    UNIVERSE_GET_SETTINGS: "universe.get.settings",
    UNIVERSE_SERVICE_SETTINGS_UPDATED: "universe.service.settings.updated",
    UNIVERSE_SERVICE_SETTINGS_SET: "universe.service.settings.set",
    BUILD_CONFIG_GET: "buildConfig.get",
    DEEPLINK_COMMAND: "deeplink.command",
    FATAL_ERROR_OCCURED: "FATAL_ERROR_OCCURED",
    GAME_ADDED: "game.added",
    GAME_LIST: "game.list",
    GAME_GET_RELEASE: "game.get.release",
    GAME_REMOVED: "game.removed",
    GAME_UPDATED: "game.updated",
    GO_ANKAMA_GET_URL: "goAnkama.getUrl",
    HAAPI_BAN_CLOUDFLARE: "haapi.ban.cloudflare",
    IS_MAIN_PROCESS_READY: "is.mainProcess.ready",
    LOGGER: "logger",
    LOGGER_OPEN_LOGDIR: "logger.open.logdir",
    MAIN_PROCESS_READY: "mainProcess.ready",
    MAIN_WINDOW_FULLY_LOADED: "windows.main.fullyLoaded",
    MAIN_WINDOW_READY: "windows.main.ready",
    SPAWN_SCRIPT: "spawnScript",
    SPAWN_SCRIPT_RESULT: "spawnScript.result",
    TERMS_ACCEPT: "terms.accept",
    TERMS_GET: "terms.get",
    TERMS_NEEDS_TO_ACCEPT_NEW_VERSION: "terms.needsToAcceptNewVersion",
    TERMS_REFUSE: "terms.refuse",
    WINDOW_PROTECT_CONTENT: "window.protect.content",
    ZAAP_SET_BADGE: "set.notif.badge",
    HOME_GET_DEFAULT_CONFIGS: "home.get.default.configs",
    HOME_GET_WIDGET_TYPES: "home.get.widget.types",
    KARD_GET_LIST: "kard.get.list",
    KARD_CONSUME_BY_CODE: "kard.consume.by.code",
    KARD_CONSUME_CODE_PASS_CULTURE: "consume.code.pass.culture",
    KARD_CONSUME_BY_ID: "kard.consume.by.id",
    KPI_USER_EXPERIENCE: "kpi.user.experience",
    NOTIFICATION_SHOW: "notification.show",
    NOTIFICATION_CLICK: "notification.click",
    NOTIFICATION_CLOSE: "notification.close",
    NOTIFICATION_FADE: "notification.fade",
    NOTIFICATION_MANAGER_READY: "notification.manager.ready",
    NOTIFICATION_MANAGER_CHANGE_HITBOX: "notification.manager.change.hitbox"
}
const ZAAP_SETTINGS = {};
["AUTO_LAUNCH", "ENABLE_ANIMATIONS", "ENABLE_VIDEO", "FAVORITE_RELEASES", "FIRSTLAUNCH", "GAME_PLAY_MODE", "IMAGE_QUALITY", "INTERFACE_SIZE", "KEEP_AT_GAME_LAUNCH", "LANGUAGE", "LOCK_HOME", "PRESELECT_PERFORMANCE", "REMEMBER_ME", "STAY_LOGGED_IN", "THEME_BY_UNIVERSE", "TRAY_AT_CLOSE", "TRAY_AT_MINIMIZE", "TUTORIAL_MADE", "ACCEPTED_TERMS_VERSION", "DEVICE_UID", "GAMES_LIST", "LAST_AUTHENTICATED_LOGIN", "LAST_ROUTE", "UNIVERSE", "LAST_GAME_ROUTE", "USER_ACCOUNTS", "WIDGETS", "LAST_READ_CHANGELOG", "WINDOWS_SIZE", "WINDOW_MAXIMIZED", "OLD_DIRECTORY", "OS_ARCHITECTURE", "CHAT_NOTIFICATION", "CHAT_MESSAGE_NOTIFICATION", "CHAT_INVITE_NOTIFICATION", "CHAT_FRIEND_CONNECTION_NOTIFICATION", "FRIENDS_SHOW_ALL", "REFUSE_FRIEND_INVITE", "IS_USER_BUSY", "CHAT_STATE", "CHAT_FONT_SIZE", "CHAT_COLOR", "VOD_ACCESS_TOKEN", "IS_VIDEO_TERMS_ACCEPTED", "VOD_AUTOPLAY", "VOD_AUDIO_TRACK_LANGUAGE", "VOD_TEXT_TRACK_LANGUAGE", "WEBTOONS_PLAYER_OPTIONS_BAR", "CONFIRM_ACCOUNT_PURCHASE", "ENABLE_SWITCH_ACCOUNT_POPUP", "ALWAYS_SHOW_MULTI_ACCOUNT_GAME_BUTTON", "LIVESTREAMS_NOTIFICATION", "TWITCH_LANG", "AUTO_DL_SPEED", "CYTRUS_DL_SPEED", "CYTRUS_MAX_RAM", "UPDATE_FINISHED_NOTIFICATION"].forEach((function(e) {
    ZAAP_SETTINGS[e] = e
}));
export default ZAAP_CONFIG;