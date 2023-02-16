CREATE TABLE `users`
(
    `id`             bigint       NOT NULL AUTO_INCREMENT,
    `email`          varchar(255) DEFAULT NULL,
    `email_verified` bit(1)       DEFAULT NULL,
    `image_url`      varchar(255) DEFAULT NULL,
    `name`           varchar(255) DEFAULT NULL,
    `password`       varchar(255) DEFAULT NULL,
    `provider`       varchar(255) NOT NULL,
    `provider_id`    varchar(255) DEFAULT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
