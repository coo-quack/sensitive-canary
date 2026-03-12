import { defineConfig } from "vitepress";

export default defineConfig({
	title: "Sensitive Canary",
	description: "Claude Code hooks that guard secrets and PII before they reach the API",
	base: "/sensitive-canary/",

	themeConfig: {
		logo: "/logo.svg",

		nav: [
			{ text: "Home", link: "/" },
			{ text: "Install", link: "/install" },
			{ text: "Rules", link: "/rules" },
			{ text: "Changelog", link: "/changelog" },
		],

		sidebar: [
			{
				text: "Guide",
				items: [
					{ text: "Getting Started", link: "/" },
					{ text: "Installation", link: "/install" },
				],
			},
			{
				text: "Reference",
				items: [
					{ text: "Detection Rules", link: "/rules" },
					{ text: "Changelog", link: "/changelog" },
				],
			},
		],

		socialLinks: [
			{ icon: "github", link: "https://github.com/coo-quack/sensitive-canary" },
		],

		footer: {
			message: "Released under the MIT License.",
			copyright: "Copyright © 2026 coo-quack",
		},

		search: {
			provider: "local",
		},
	},

	head: [
		[
			"link",
			{ rel: "icon", type: "image/svg+xml", href: "/sensitive-canary/logo.svg" },
		],
	],
});
