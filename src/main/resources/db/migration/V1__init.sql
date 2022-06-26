create table users
(
    id bigserial primary key,
    name varchar,
    password varchar,
    username  varchar
);

create table roles
(
    id bigserial primary key,
    name varchar
);

create table users_roles
(
    user_id bigint references users(id),
    role_id bigint references roles(id),
    constraint user_roles_pk primary key (user_id, role_id)
);

alter table users
    add constraint unique_username unique (username);

alter table roles
    add constraint unique_role unique (name);

insert into roles(name)
values ('ROLE_USER'),
       ('ROLE_MANAGER'),
       ('ROLE_ADMIN'),
       ('ROLE_SUPER_ADMIN');

insert into users(name, password, username)
values ('John Travolta', '$2a$12$pH3q.RV92l9TrOpUbaSvxOXcC37lvXeMAwIs0UVUybCaq2LECboxu', 'john'),
       ('Will Smith', '$2a$12$pH3q.RV92l9TrOpUbaSvxOXcC37lvXeMAwIs0UVUybCaq2LECboxu', 'will'),
       ('Jim Carry', '$2a$12$pH3q.RV92l9TrOpUbaSvxOXcC37lvXeMAwIs0UVUybCaq2LECboxu', 'jim'),
       ('Arnold Schwarzenegger', '$2a$12$pH3q.RV92l9TrOpUbaSvxOXcC37lvXeMAwIs0UVUybCaq2LECboxu', 'arnold');

insert into users_roles(user_id, role_id)
values (1,1),
       (1,2),
       (2,2),
       (3,3),
       (4,4),
       (4,3),
       (4,1);

