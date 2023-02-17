CREATE TABLE `users`
(
    `id`                   bigint       NOT NULL AUTO_INCREMENT,
    `email`                varchar(255)                                                   DEFAULT NULL,
    `email_verified`       bit(1)                                                         DEFAULT NULL,
    `image_url`            varchar(255)                                                   DEFAULT NULL,
    `name`                 varchar(255)                                                   DEFAULT NULL,
    `password`             varchar(255)                                                   DEFAULT NULL,
    `provider`             varchar(255) NOT NULL,
    `provider_id`          varchar(255)                                                   DEFAULT NULL,
    `access_token`         varchar(2000) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
    `refresh_token`        varchar(2000) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
    `expires_time`         timestamp NULL DEFAULT NULL,
    `expires_refresh_time` timestamp NULL DEFAULT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
