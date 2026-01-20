import type {
  ExpressiveCodeConfig,
  LicenseConfig,
  NavBarConfig,
  ProfileConfig,
  SiteConfig,
} from "./types/config";
import { LinkPreset } from "./types/config";

export const siteConfig: SiteConfig = {
  title: "0xm3dd",
  subtitle: "Cybersecurity Enthusiast | Penetration Testing & Red Teaming | CTF Player",
  lang: "en",
  themeColor: {
    hue: 150, // This is the 'Kali Linux' Neon Green color
    fixed: true, // Forces the green theme so visitors see it immediately
  },
  banner: {
    enable: true, // kept false for a clean look, enable if you have a cool header.png later
    src: "assets/images/ken.png",
    position: "center",
    credit: {
      enable: false,
      text: "",
      url: "",
    },
  },
  toc: {
    enable: true, // Essential for long CTF writeups
    depth: 3, // Increased depth so sub-sections (like 1.1, 1.2) appear in the menu
  },
  favicon: [
    // Leave empty to use default or add your logo path here later
  ],
};

export const navBarConfig: NavBarConfig = {
  links: [
    LinkPreset.Home,
    {
      name: "Writeups",
      url: "/categories/", // Auto-filters for "Writeups"
      external: false,
    },
    {
      name: "Notes",
      url: "/notes/",    // Auto-filters for "Notes"
      external: false,
    },
    LinkPreset.Archive, // The "Timeline" view (good for seeing activity)
    LinkPreset.About,
    {
      name: "Status",
      url: "/status/",
      external: false,
    },
  ],
};

export const profileConfig: ProfileConfig = {
  avatar: "assets/images/avatar.png", // REMINDER: Rename your logo file to 'avatar.png' and put it in src/assets/images/
  name: "0xm3dd",
  bio: "Cybersecurity Student | Red Teaming | Penetration Testing & CTF Player",
  links: [
    {
      name: "GitHub",
      icon: "fa6-brands:github",
      url: "https://github.com/0xm3dd",
    },
    {
      name: "LinkedIn",
      icon: "fa6-brands:linkedin", // Professional link
      url: "https://www.linkedin.com/in/mohammed-elfadlaoui-644a4b297/", // UPDATE THIS
    },
    {
      name: "Twitter",
      icon: "fa6-brands:twitter",
      url: "https://x.com/0xm3dd", // Update or remove if unused
    },
  ],
};

export const licenseConfig: LicenseConfig = {
  enable: true,
  name: "CC BY-NC-SA 4.0",
  url: "https://creativecommons.org/licenses/by-nc-sa/4.0/",
};

export const expressiveCodeConfig: ExpressiveCodeConfig = {
  // 'github-dark' fits the Kali aesthetic perfectly
  theme: "github-dark",
};
