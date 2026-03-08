/**
 * Фабрика Творцов — Telegram Mini App Auth & Decryption
 * 
 * Проверяет доступ через Telegram WebApp API и расшифровывает контент.
 * Использует Web Crypto API (AES-CBC) для расшифровки.
 */

(function () {
    'use strict';

    // ========================
    // Утилиты для шифрования
    // ========================

    function base64ToBytes(base64) {
        const binStr = atob(base64);
        const bytes = new Uint8Array(binStr.length);
        for (let i = 0; i < binStr.length; i++) {
            bytes[i] = binStr.charCodeAt(i);
        }
        return bytes;
    }

    function hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    async function decryptAES(encryptedBase64, keyHex) {
        const encData = base64ToBytes(encryptedBase64);
        // Первые 16 байт — IV
        const iv = encData.slice(0, 16);
        const ciphertext = encData.slice(16);

        const keyBytes = hexToBytes(keyHex);
        const cryptoKey = await crypto.subtle.importKey(
            'raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: iv }, cryptoKey, ciphertext
        );

        return new TextDecoder().decode(decrypted);
    }

    async function hashId(userId) {
        // Хешируем ID (превращенный в строку) через SHA-256
        const msgUint8 = new TextEncoder().encode(String(userId));
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    // ========================
    // Проверка доступа
    // ========================

    async function checkAccessAsync() {
        const tg = window.Telegram && window.Telegram.WebApp;

        // Проверяем, открыто ли через Telegram
        if (!tg || !tg.initDataUnsafe || !tg.initDataUnsafe.user) {
            return { allowed: false, reason: 'not_telegram' };
        }

        const userId = tg.initDataUnsafe.user.id;
        const hashedUserId = await hashId(userId);

        // Проверяем, есть ли пользователь в списке
        if (typeof ALLOWED_USERS === 'undefined' || !ALLOWED_USERS.includes(hashedUserId)) {
            return { allowed: false, reason: 'not_allowed', userId: userId };
        }

        return { allowed: true, userId: userId, user: tg.initDataUnsafe.user };
    }

    // ========================
    // UI
    // ========================

    function showAccessDenied(reason, userId) {
        const main = document.querySelector('main') || document.querySelector('.main');
        if (!main) return;

        let message = '';
        if (reason === 'not_telegram') {
            message = `
                <div style="text-align:center; padding: 60px 20px;">
                    <div style="font-size: 64px; margin-bottom: 20px;">🔒</div>
                    <h2 style="color: #fff; margin-bottom: 12px;">Доступ закрыт</h2>
                    <p style="color: rgba(255,255,255,0.6); max-width: 400px; margin: 0 auto; line-height: 1.6;">
                        Этот курс доступен только через Telegram.<br>
                        Откройте приложение через бота в Telegram.
                    </p>
                </div>
            `;
        } else {
            message = `
                <div style="text-align:center; padding: 60px 20px;">
                    <div style="font-size: 64px; margin-bottom: 20px;">⛔</div>
                    <h2 style="color: #fff; margin-bottom: 12px;">Нет доступа</h2>
                    <p style="color: rgba(255,255,255,0.6); max-width: 400px; margin: 0 auto; line-height: 1.6;">
                        У вас нет доступа к этому курсу.<br>
                        Обратитесь к администратору для получения доступа.
                    </p>
                    ${userId ? `<p style="color: rgba(255,255,255,0.3); margin-top: 20px; font-size: 12px;">Ваш ID: ${userId}</p>` : ''}
                </div>
            `;
        }

        main.innerHTML = message;
    }

    function showDecryptionError() {
        const main = document.querySelector('main') || document.querySelector('.main');
        if (!main) return;
        main.innerHTML = `
            <div style="text-align:center; padding: 60px 20px;">
                <div style="font-size: 64px; margin-bottom: 20px;">⚠️</div>
                <h2 style="color: #fff; margin-bottom: 12px;">Ошибка загрузки</h2>
                <p style="color: rgba(255,255,255,0.6);">
                    Не удалось расшифровать контент. Попробуйте перезагрузить страницу.
                </p>
            </div>
        `;
    }

    // ========================
    // Расшифровка контента
    // ========================

    async function decryptAllContent() {
        const encryptedElements = document.querySelectorAll('.encrypted-content');

        if (encryptedElements.length === 0) {
            // Нет зашифрованных элементов — страница без защиты (index.html может быть открытой)
            return true;
        }

        const key = typeof ENCRYPTION_KEY !== 'undefined' ? ENCRYPTION_KEY : null;
        if (!key || key === 'PLACEHOLDER_KEY') {
            console.error('Encryption key not set');
            return false;
        }

        try {
            for (const el of encryptedElements) {
                const encData = el.getAttribute('data-enc');
                if (!encData) continue;

                const decryptedHTML = await decryptAES(encData, key);
                // Создаём временный контейнер
                const temp = document.createElement('div');
                temp.innerHTML = decryptedHTML;

                // Заменяем зашифрованный элемент расшифрованным контентом
                el.replaceWith(...temp.childNodes);
            }
            return true;
        } catch (e) {
            console.error('Decryption failed:', e);
            return false;
        }
    }

    // ========================
    // Инициализация
    // ========================

    async function init() {
        // Настраиваем Telegram WebApp
        const tg = window.Telegram && window.Telegram.WebApp;
        if (tg) {
            tg.ready();
            tg.expand(); // Раскрыть на весь экран

            // Адаптируем тему
            if (tg.themeParams) {
                document.documentElement.style.setProperty('--tg-bg', tg.themeParams.bg_color || '#0a0a1a');
                document.documentElement.style.setProperty('--tg-text', tg.themeParams.text_color || '#ffffff');
            }

            // Кнопка "Назад"
            tg.BackButton.show();
            tg.BackButton.onClick(function () {
                window.history.back();
            });
        }

        // Проверяем доступ (теперь асинхронно)
        const access = await checkAccessAsync();

        if (!access.allowed) {
            showAccessDenied(access.reason, access.userId);
            return;
        }

        // Расшифровываем контент
        const success = await decryptAllContent();
        if (!success) {
            showDecryptionError();
        }
    }

    // Запуск после полной загрузки DOM
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
