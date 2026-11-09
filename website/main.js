/*
 * Motion for the NEXUS site. The page is complete without any of this: CSS gives the final,
 * static layout, and this file only adds parallax and the exploded-packet reveal for people who
 * have not asked for reduced motion, on screens wide enough to carry it. Transforms only; nothing
 * animates width, height, top or left.
 */
(() => {
  // Navigation gains a ground once the page has moved.
  const nav = document.getElementById("nav");
  if (nav && "IntersectionObserver" in window) {
    const sentinel = document.createElement("div");
    sentinel.setAttribute("aria-hidden", "true");
    sentinel.style.cssText = "position:absolute;top:0;left:0;width:1px;height:48px;pointer-events:none";
    document.body.prepend(sentinel);
    new IntersectionObserver(([e]) => nav.classList.toggle("is-stuck", !e.isIntersecting)).observe(sentinel);
  }

  if (!window.gsap || !window.ScrollTrigger) return;
  gsap.registerPlugin(ScrollTrigger);

  const mm = gsap.matchMedia();
  mm.add("(prefers-reduced-motion: no-preference) and (min-width: 40rem)", () => {
    const scrub = 0.6;

    // The valley: layers drift at different depths. depth is a fraction of the hero's height that
    // the layer travels over one hero's worth of scroll. Positive lags behind the page, negative runs ahead.
    const hero = document.querySelector(".hero");
    document.querySelectorAll(".scene [data-depth]").forEach((layer) => {
      const depth = parseFloat(layer.dataset.depth);
      const drift = parseFloat(layer.dataset.drift || "0");
      if (!depth && !drift) return;
      gsap.to(layer, {
        y: () => depth * hero.offsetHeight,
        xPercent: drift,
        ease: "none",
        scrollTrigger: { trigger: hero, start: "top top", end: "bottom top", scrub },
      });
    });

    // The packet: layers start stacked, each showing only its title strip, and settle apart as the section scrolls into view.
    const stack = document.querySelector(".stack");
    const cards = gsap.utils.toArray(".layer-card");
    if (stack && cards.length) {
      const peek = 44;
      cards.forEach((card, i) => {
        gsap.fromTo(
          card,
          { y: () => -(card.offsetTop - i * peek), opacity: 1 },
          {
            y: 0,
            opacity: 1,
            ease: "none",
            immediateRender: true,
            scrollTrigger: { trigger: stack, start: "top 88%", end: "top 28%", scrub },
          },
        );
      });
    }

    // Product plates: the picture drifts inside its frame while the frame holds still.
    gsap.utils.toArray(".frame").forEach((frame) => {
      const img = frame.querySelector("img");
      if (!img) return;
      gsap.fromTo(
        img,
        { yPercent: -4.5 },
        { yPercent: 4.5, ease: "none", scrollTrigger: { trigger: frame, start: "top bottom", end: "bottom top", scrub } },
      );
    });

    // The seam is drawn as the limits are read.
    const seam = document.getElementById("seam");
    if (seam) {
      const len = seam.getTotalLength();
      gsap.set(seam, { strokeDasharray: len, strokeDashoffset: len });
      gsap.to(seam, {
        strokeDashoffset: 0,
        ease: "none",
        scrollTrigger: { trigger: ".limits", start: "top 70%", end: "bottom 55%", scrub },
      });
    }
  });
})();
