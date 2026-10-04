'use client';

import { useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import * as THREE from 'three';

/**
 * Lightweight WebGL scene for the hero. It deliberately owns only its canvas,
 * keeping the surrounding landing page server-rendered.
 */
export function ThreatSphere() {
  const host = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = host.current;
    if (!container || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 100);
    camera.position.set(0, 0, 7.5);

    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'high-performance' });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.75));
    renderer.setClearColor(0x000000, 0);
    container.appendChild(renderer.domElement);

    const shield = new THREE.Group();
    scene.add(shield);

    const core = new THREE.Mesh(
      new THREE.IcosahedronGeometry(1.35, 2),
      new THREE.MeshBasicMaterial({ color: 0x8b5cf6, wireframe: true, transparent: true, opacity: 0.56 }),
    );
    shield.add(core);

    const haloMaterial = new THREE.MeshBasicMaterial({ color: 0xc4b5fd, transparent: true, opacity: 0.12, side: THREE.DoubleSide });
    const halo = new THREE.Mesh(new THREE.TorusGeometry(1.82, 0.012, 6, 120), haloMaterial);
    halo.rotation.x = Math.PI * 0.34;
    shield.add(halo);
    const haloTwo = halo.clone();
    haloTwo.scale.set(1.22, 1.22, 1.22);
    haloTwo.rotation.set(Math.PI * 0.66, Math.PI * 0.35, 0);
    shield.add(haloTwo);

    const pointCount = 140;
    const points = new Float32Array(pointCount * 3);
    for (let i = 0; i < pointCount; i++) {
      const radius = 2.1 + Math.random() * 1.65;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      points[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
      points[i * 3 + 1] = radius * Math.cos(phi);
      points[i * 3 + 2] = radius * Math.sin(phi) * Math.sin(theta);
    }
    const pointGeometry = new THREE.BufferGeometry();
    pointGeometry.setAttribute('position', new THREE.BufferAttribute(points, 3));
    const particleField = new THREE.Points(
      pointGeometry,
      new THREE.PointsMaterial({ color: 0xa78bfa, size: 0.032, transparent: true, opacity: 0.74, sizeAttenuation: true }),
    );
    scene.add(particleField);

    const glow = new THREE.PointLight(0xa78bfa, 3, 10);
    glow.position.set(0, 0, 2);
    scene.add(glow);

    const pointer = { x: 0, y: 0 };
    const onPointerMove = (event: PointerEvent) => {
      const rect = container.getBoundingClientRect();
      pointer.x = ((event.clientX - rect.left) / rect.width - 0.5) * 2;
      pointer.y = ((event.clientY - rect.top) / rect.height - 0.5) * 2;
    };
    container.addEventListener('pointermove', onPointerMove);

    const resize = () => {
      const { width, height } = container.getBoundingClientRect();
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height, false);
    };
    const observer = new ResizeObserver(resize);
    observer.observe(container);
    resize();

    const intro = gsap.timeline();
    intro.fromTo(shield.scale, { x: 0.55, y: 0.55, z: 0.55 }, { x: 1, y: 1, z: 1, duration: 1.35, ease: 'power3.out' });
    intro.fromTo(haloMaterial, { opacity: 0 }, { opacity: 0.17, duration: 0.9, ease: 'sine.out' }, 0.18);
    const breathe = gsap.to(core.material, { opacity: 0.28, duration: 1.8, repeat: -1, yoyo: true, ease: 'sine.inOut' });

    let frame = 0;
    const render = () => {
      frame = requestAnimationFrame(render);
      shield.rotation.y += (pointer.x * 0.34 - shield.rotation.y) * 0.025;
      shield.rotation.x += (-pointer.y * 0.18 - shield.rotation.x) * 0.025;
      shield.rotation.z += 0.0017;
      particleField.rotation.y -= 0.0008;
      particleField.rotation.x += 0.00025;
      halo.rotation.z += 0.003;
      haloTwo.rotation.z -= 0.002;
      renderer.render(scene, camera);
    };
    render();

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      container.removeEventListener('pointermove', onPointerMove);
      intro.kill();
      breathe.kill();
      core.geometry.dispose();
      (core.material as THREE.Material).dispose();
      halo.geometry.dispose();
      haloMaterial.dispose();
      pointGeometry.dispose();
      (particleField.material as THREE.Material).dispose();
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, []);

  return (
    <div className="lp-threat-sphere relative aspect-square w-full max-w-[580px]" aria-hidden ref={host}>
      <div className="lp-threat-reticle absolute inset-[18%] rounded-full" />
      <div className="lp-threat-label lp-mono absolute top-[17%] left-[5%]">LIVE / THREAT MAP</div>
      <div className="lp-threat-label lp-mono absolute right-[5%] bottom-[17%] text-right">POLICY<br />ENFORCED</div>
      <div className="lp-threat-core lp-mono absolute top-1/2 left-1/2 grid size-20 -translate-x-1/2 -translate-y-1/2 place-items-center rounded-full text-center text-[10px] leading-tight text-white">DEP<br />GUARD</div>
    </div>
  );
}
